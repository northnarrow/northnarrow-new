//! Regression guard for the respawn-v2 unit contract
//! (docs/design/WATCHDOG_RESPAWN_V2_DESIGN.md §4): parses the shipped
//! unit files so a well-meaning edit cannot silently re-introduce
//! `BindsTo=` (watchdog stopped on agent crash) or re-enable systemd's
//! start-rate limiter / auto-restart on the agent unit.

use std::path::PathBuf;

fn unit(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("deploy")
        .join("systemd")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
}

/// Non-comment `Key=Value` lines.
fn directives(body: &str) -> Vec<(String, String)> {
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('['))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

fn value<'a>(d: &'a [(String, String)], key: &str) -> Option<&'a str> {
    d.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

#[test]
fn watchdog_unit_has_no_bindsto_and_wants_the_agent() {
    let d = directives(&unit("northnarrow-watchdog.service"));
    assert!(
        value(&d, "BindsTo").is_none(),
        "BindsTo= stops the watchdog on an agent CRASH (design §1 #3)"
    );
    assert_eq!(value(&d, "Wants"), Some("northnarrow-agent.service"));
    assert_eq!(value(&d, "After"), Some("northnarrow-agent.service"));
    assert_eq!(value(&d, "Restart"), Some("on-failure"));
}

#[test]
fn watchdog_execstart_names_the_agent_unit_and_binary() {
    let body = unit("northnarrow-watchdog.service");
    // ExecStart is a multi-line directive (backslash continuations).
    let exec: String = body
        .lines()
        .skip_while(|l| !l.starts_with("ExecStart="))
        .take_while(|l| {
            l.starts_with("ExecStart=") || l.trim_end().ends_with('\\') || l.starts_with("    ")
        })
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        exec.contains("--agent-unit northnarrow-agent.service"),
        "{exec}"
    );
    assert!(
        exec.contains("--agent-bin /usr/local/bin/northnarrow-agent"),
        "{exec}"
    );
}

#[test]
fn agent_unit_keeps_restart_no_and_disables_start_rate_limit() {
    let d = directives(&unit("northnarrow-agent.service"));
    assert_eq!(
        value(&d, "Restart"),
        Some("no"),
        "restart policy lives ONLY in the watchdog (design §2.3)"
    );
    assert_eq!(
        value(&d, "StartLimitIntervalSec"),
        Some("0"),
        "systemd's start-rate limiter must not veto the watchdog's backoff"
    );
    assert_eq!(value(&d, "Type"), Some("notify"));
    let caps = value(&d, "CapabilityBoundingSet").expect("bounding set");
    assert!(caps.split_whitespace().any(|c| c == "CAP_KILL"), "{caps}");
}
