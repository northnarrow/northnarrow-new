//! Lab PR 236: an engine built the way `main.rs` builds it, over host state
//! given by the caller — the golden replay's fixture host (lab PR 228), or
//! `nn-admin policy test`'s offline host (the shipped lists, a `/proc` of
//! its own) — and the decision of one event as `process_event` takes it.
//!
//! Nothing here executes a response: a decision is data.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use crate::decision::host::DecisionHost;
use nn_model::Event;
use parking_lot::Mutex;
use serde_json::{json, Value};

use super::attack::mitre_of;
use super::combine::Decision;
use super::correlation::{AncestryTree, CorrelationStore};
use super::rule_policy::{PolicyHandle, RulePolicy};
use super::rules::{epg, net::NetRuleConfig, net_fanout::FanoutConfig};
use super::{Rule, RuleEngine};
use crate::config::comm_allowlist::{
    load_comm_allowlist, NETFLOW_COMM_ALLOWLIST_SHIPPED, PROCESS_COMM_ALLOWLIST_SHIPPED,
};
use crate::config::overlay_auth::Verified;
use crate::impact::RansomTracker;
use crate::impair::{DefenseDetector, SecurityTools};
use crate::net::blocklist::{Ja3Blocklist, NetBlocklist};
use crate::posture::lineage::AuthSessionTracker;

/// The host an offline engine runs over.
///
/// R08b (lab PR 251): `H` is the host the engine runs on (the agent's
/// `LinuxHost`; the replay's lineage and tracker are on it too).
pub struct HostParts<'a, H: DecisionHost> {
    /// Where the shipped lists (`*.v1`) are read; a missing one is the copy
    /// built into the agent.
    pub configs: &'a Path,
    /// The `/proc` the engine reads (an empty directory: nothing of the
    /// machine running the replay).
    pub proc_root: &'a Path,
    pub lineage: AuthSessionTracker<H>,
    pub ransom: Arc<RansomTracker<H>>,
    /// The configured resolvers (the port-53 exemption, lab PR 224).
    pub resolvers: Vec<IpAddr>,
    /// The per-rule policy the engine reads.
    pub policy: RulePolicy,
}

/// The production engine over `host` (`RuleEngine::with_default_rules_and_net`
/// with the shipped lists and no overlay).
pub fn engine<H: DecisionHost>(host: HostParts<'_, H>) -> RuleEngine<H> {
    let HostParts {
        configs,
        proc_root,
        lineage,
        ransom,
        resolvers,
        policy,
    } = host;
    let file = |f: &str| configs.join(f);
    let process_allowlist = Arc::new(
        load_comm_allowlist(
            "process-comm-allowlist",
            &file("process-comm-allowlist.v1"),
            PROCESS_COMM_ALLOWLIST_SHIPPED,
            &Verified::Missing,
        )
        .unwrap_or_default(),
    );
    let netflow_allowlist = Arc::new(
        load_comm_allowlist(
            "netflow-comm-allowlist",
            &file("netflow-comm-allowlist.v1"),
            NETFLOW_COMM_ALLOWLIST_SHIPPED,
            &Verified::Missing,
        )
        .unwrap_or_default(),
    );
    let (tools, _) = SecurityTools::load::<H>(&file("security-tools.v1"));
    let defense = Arc::new(DefenseDetector::with_proc_root(
        Arc::new(tools),
        lineage.clone(),
        Some(Arc::new(
            process_allowlist
                .as_ref()
                .clone()
                .with_identity(lineage.clone()),
        )),
        proc_root,
    ));
    let correlation = Arc::new(Mutex::new(CorrelationStore::with_tree(
        AncestryTree::with_proc_root(proc_root, super::correlation::ancestry::MAX_TRACKED_EDGES),
    )));
    let net_config = NetRuleConfig {
        resolvers: crate::net::resolvers::HostResolvers::fixed(resolvers),
        fanout: Arc::new(FanoutConfig::default()),
    };
    RuleEngine::with_default_rules_and_net(
        Arc::new(
            NetBlocklist::load::<H>(&file("netflow-blocklist.v1"), &Verified::Missing)
                .unwrap_or_default(),
        ),
        Arc::new(
            Ja3Blocklist::load::<H>(&file("netflow-ja3-blocklist.v1"), &Verified::Missing)
                .unwrap_or_default(),
        ),
        Arc::new(Mutex::new(super::rules::net::DnsBurstWindow::new())),
        process_allowlist,
        netflow_allowlist,
        Arc::new(Mutex::new(super::rules::net::BeaconWindow::new())),
        Arc::new(crate::net::dns_cache::DnsCache::default()),
        H::inert_installer_window(),
        lineage,
        crate::canary::readers::CanaryReaders::default(),
        correlation,
        net_config,
        ransom,
        defense,
    )
    .with_policy(PolicyHandle::new(policy))
    .with_facts(H::actor_facts(proc_root))
}

/// The decision on one event, as `process_event` takes it: an exec is
/// first ingested into the lineage cache; an anti-tamper denial is
/// NN-L-AT-001's and an exploit post-condition NN-L-EPG-001/002's, outside
/// the engine; every other event goes to the engine.
pub fn decide<H: DecisionHost>(
    engine: &RuleEngine<H>,
    lineage: &AuthSessionTracker<H>,
    event: &Event,
) -> Value {
    lineage.ingest_spawn_event(event);
    match event {
        Event::FsProtectDenial { .. } => {
            let at001 = super::rules::anti_tamper::NnLAt001AntiTamperDenial;
            outside_line(at001.evaluate(event), at001.attack(), None)
        }
        Event::ExploitPostcondition { .. } => {
            let rule = epg::rule_for(event);
            let v = rule.and_then(|r| r.evaluate(event));
            let response = v.as_ref().map(|_| epg::response_line(event));
            outside_line(v, rule.map_or(&[][..], |r| r.attack()), response)
        }
        _ => decision_line(engine.decide(event).as_ref()),
    }
}

/// Lab PR 267 (R12a): what the bus does for an exec an event of a higher
/// class overtakes (`nn_linux::sensors::bus`): the lineage ingests it and
/// the engine's rules learn its place in the process tree
/// ([`RuleEngine::observe_arrival`]); judging it later changes neither.
pub fn arrive<H: DecisionHost>(
    engine: &RuleEngine<H>,
    lineage: &AuthSessionTracker<H>,
    event: &Event,
) {
    if lineage.ingest_spawn_event(event) {
        engine.observe_arrival(event);
    }
}

/// A verdict made outside the engine (one rule), as a decision line.
pub fn outside_line(
    v: Option<nn_model::Verdict>,
    attack: &[super::attack::AttackRef],
    response: Option<String>,
) -> Value {
    let Some(v) = v else {
        return Value::Null;
    };
    let mut line = verdict_json(&v, attack);
    if let Some(r) = response {
        line["response"] = Value::String(r);
    }
    line
}

fn verdict_json(v: &nn_model::Verdict, attack: &[super::attack::AttackRef]) -> Value {
    json!({
        "rule": v.rule_id,
        "name": v.rule_name,
        "category": v.category,
        "action": format!("{:?}", v.action),
        "severity": format!("{:?}", v.severity),
        "pid": v.event_pid,
        "file": v.event_filename,
        "ts": v.timestamp_ns,
        "reasoning": v.reasoning,
        "mitre": serde_json::to_value(mitre_of(attack)).unwrap_or(Value::Null),
    })
}

/// One engine decision as a line: the decision's verdict and ATT&CK
/// union; with several matches, each match (rule, action, severity, mode,
/// target, ATT&CK) and the responses that would run.
pub fn decision_line(d: Option<&Decision>) -> Value {
    let Some(d) = d else {
        return Value::Null;
    };
    let mut line = verdict_json(&d.verdict, &d.attack());
    if d.matches.len() > 1
        || d.primary().applied != super::combine::Applied::Builtin
        || d.primary()
            .held
            .is_some_and(|h| h == super::combine::LEGACY_CEILING)
    {
        line["matches"] = Value::Array(
            d.matches
                .iter()
                .map(|m| {
                    let mut e = json!({
                        "rule": m.rule_id,
                        "action": format!("{:?}", m.verdict.action),
                        "severity": format!("{:?}", m.verdict.severity),
                        "mode": m.applied.name(),
                        "pid": m.verdict.event_pid,
                        "mitre": serde_json::to_value(mitre_of(m.attack)).unwrap_or(Value::Null),
                    });
                    if let Some(h) = m.held {
                        e["held"] = Value::String(h.to_string());
                    }
                    if let Some(a) = &m.held_action {
                        e["held_action"] = Value::String(format!("{a:?}"));
                    }
                    if let super::combine::Applied::Exempt(why) = &m.applied {
                        e["exempt"] = Value::String(why.clone());
                    }
                    e
                })
                .collect(),
        );
        line["responses"] = Value::Array(
            d.responses
                .iter()
                .map(|r| {
                    json!({
                        "action": format!("{:?}", r.action),
                        "pid": r.pid,
                        "rule": r.rule_id,
                    })
                })
                .collect(),
        );
    }
    line
}

/// The events of a sample file for `nn-admin policy test`: one
/// `nn_model::Event` JSON per line, or one `{"event": …}` per line, or a
/// golden case (`{"items": [{"event": …}, …]}`; its other items are
/// skipped, said so in `skipped`).
pub fn sample_events(text: &str) -> anyhow::Result<(Vec<Event>, usize)> {
    use anyhow::Context as _;
    let trimmed = text.trim_start();
    let mut skipped = 0;
    let mut out = Vec::new();
    let one = |v: Value| -> anyhow::Result<Option<Event>> {
        let v = match v {
            Value::Object(mut o) if o.len() == 1 && o.contains_key("event") => {
                o.remove("event").unwrap_or(Value::Null)
            }
            Value::Object(o) if o.len() == 1 && !o.contains_key("event") => {
                let (k, _) = o.iter().next().expect("one key");
                if matches!(k.as_str(), "tcp_sweep" | "execpol") {
                    return Ok(None);
                }
                Value::Object(o)
            }
            v => v,
        };
        Ok(Some(serde_json::from_value(v).context("not an event")?))
    };
    if trimmed.starts_with('{') && trimmed.contains("\"items\"") {
        if let Ok(Value::Object(mut case)) = serde_json::from_str::<Value>(text) {
            if let Some(Value::Array(items)) = case.remove("items") {
                for (i, item) in items.into_iter().enumerate() {
                    match one(item).with_context(|| format!("item {i}"))? {
                        Some(e) => out.push(e),
                        None => skipped += 1,
                    }
                }
                return Ok((out, skipped));
            }
        }
    }
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let v: Value =
            serde_json::from_str(line).with_context(|| format!("line {}: not JSON", i + 1))?;
        match one(v).with_context(|| format!("line {}", i + 1))? {
            Some(e) => out.push(e),
            None => skipped += 1,
        }
    }
    Ok((out, skipped))
}

/// `nn-admin policy test`: `events` through an offline engine (the lists
/// of `configs`, an empty `/proc` at `proc_root`) under `policy`, one
/// decision line each (`null`: no rule matched). Nothing is executed,
/// signed or stored.
pub fn policy_test<H: DecisionHost>(
    policy: RulePolicy,
    events: &[Event],
    configs: &Path,
    proc_root: &Path,
) -> Vec<Value> {
    let lineage = AuthSessionTracker::<H>::new(proc_root);
    let engine = engine(HostParts {
        configs,
        proc_root,
        lineage: lineage.clone(),
        ransom: Arc::new(RansomTracker::new(lineage.clone())),
        resolvers: Vec::new(),
        policy,
    });
    events
        .iter()
        .map(|e| decide(&engine, &lineage, e))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::posture::host::testing::TestHost as H;

    fn policy_test(
        policy: RulePolicy,
        events: &[Event],
        configs: &Path,
        proc_root: &Path,
    ) -> Vec<Value> {
        super::policy_test::<H>(policy, events, configs, proc_root)
    }

    const CONFIGS: &str = concat!(env!("NN_REPO_ROOT"), "/configs");

    fn shell_line() -> String {
        let e = crate::decision::rules::testutil::spawn("payload", "/tmp/payload");
        serde_json::to_string(&e).unwrap()
    }

    /// The three sample formats read the same events; other golden items
    /// are skipped and counted.
    #[test]
    fn sample_files_in_every_format() {
        let line = shell_line();
        let (a, s) = sample_events(&format!("{line}\n\n# c\n{line}\n")).unwrap();
        assert_eq!((a.len(), s), (2, 0));
        let (b, _) = sample_events(&format!("{{\"event\": {line}}}\n")).unwrap();
        assert_eq!(b.len(), 1);
        let case = format!(
            "{{\"about\": \"x\", \"fires\": [], \"items\": [{{\"event\": {line}}}, \
             {{\"tcp_sweep\": {{}}}}]}}"
        );
        let (c, s) = sample_events(&case).unwrap();
        assert_eq!((c.len(), s), (1, 1));
        assert!(sample_events("not json\n").is_err());
        assert!(sample_events("{\"Nope\": {}}\n").is_err());
    }

    /// A candidate policy changes the decisions printed, and nothing runs.
    #[test]
    fn policy_test_replays_under_the_candidate() {
        let proc = tempfile::TempDir::new().unwrap();
        let (events, _) = sample_events(&shell_line()).unwrap();
        let base = policy_test(
            RulePolicy::builtin(),
            &events,
            Path::new(CONFIGS),
            proc.path(),
        );
        assert_eq!(base[0]["action"], "KillProcessTree");
        let p = crate::decision::rule_policy::parse("audit R001\n").unwrap();
        let audited = policy_test(p, &events, Path::new(CONFIGS), proc.path());
        assert_eq!(audited[0]["action"], "Log");
        assert_eq!(audited[0]["matches"][0]["mode"], "audit");
        // Lists missing from the config directory: the built-in copies.
        let empty = tempfile::TempDir::new().unwrap();
        let again = policy_test(RulePolicy::builtin(), &events, empty.path(), proc.path());
        assert_eq!(again[0]["action"], "KillProcessTree");
    }
}
