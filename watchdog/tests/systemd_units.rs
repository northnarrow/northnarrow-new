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

/// External audit WDG-003: the watchdog verifies the agent's pid by its
/// `/proc/<pid>/exe`, closed to a root process without CAP_SYS_PTRACE
/// (the agent is not dumpable).
#[test]
fn watchdog_unit_can_verify_the_agents_executable() {
    let d = directives(&unit("northnarrow-watchdog.service"));
    let caps = value(&d, "CapabilityBoundingSet").expect("bounding set");
    assert!(
        caps.split_whitespace().any(|c| c == "CAP_SYS_PTRACE"),
        "{caps}"
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
    assert_eq!(
        value(&d, "RuntimeDirectoryPreserve"),
        Some("yes"),
        "/run/northnarrow is shared with the watchdog; a respawn must not wipe it"
    );
    let rw = value(&d, "ReadWritePaths").expect("ReadWritePaths");
    assert!(
        rw.split_whitespace().any(|p| p == "/etc/northnarrow"),
        "/etc/northnarrow must be writable or the audit chain / key bootstrap EROFS (etc-readonly-audit-1): {rw}"
    );
    let caps = value(&d, "CapabilityBoundingSet").expect("bounding set");
    assert!(caps.split_whitespace().any(|c| c == "CAP_KILL"), "{caps}");
}

/// External audit EBPF-001: systemd's stop signals are refused outside a
/// signed trusted-installer window, so a stop must give up quickly and
/// never escalate to a second instance beside the running one.
#[test]
fn both_units_give_up_a_refused_stop_quickly_and_never_double_start() {
    for name in ["northnarrow-agent.service", "northnarrow-watchdog.service"] {
        let d = directives(&unit(name));
        assert_eq!(
            value(&d, "TimeoutStopSec"),
            Some("5s"),
            "{name}: bounded wait on a refused stop"
        );
        assert_eq!(
            value(&d, "SendSIGKILL"),
            Some("no"),
            "{name}: with leftover processes systemd must refuse a new start"
        );
        assert_eq!(
            value(&d, "RefuseManualStop"),
            Some("yes"),
            "{name}: a manual stop must fail loudly, not report a running unit dead"
        );
    }
}

/// External audit DEP-004: an unmet `Condition*` skips a unit and reports
/// its start job as done — the agent never runs and nothing is failed. An
/// unmet `Assert*` fails the job but leaves the unit inactive (dead), and
/// would pre-empt the check below. The bpffs pre-flight is a command, so
/// without bpffs the unit is `failed` and in `systemctl --failed`.
#[test]
fn agent_unit_asserts_bpffs() {
    for name in ["northnarrow-agent.service", "northnarrow-watchdog.service"] {
        let d = directives(&unit(name));
        let skips: Vec<&str> = d
            .iter()
            .filter(|(k, _)| k.starts_with("Condition"))
            .map(|(k, _)| k.as_str())
            .collect();
        assert!(
            skips.is_empty(),
            "{name}: {skips:?} would skip the unit silently"
        );
    }
    let d = directives(&unit("northnarrow-agent.service"));
    assert!(value(&d, "AssertPathIsMountPoint").is_none());
    assert_eq!(
        value(&d, "ExecStartPre"),
        Some("/usr/bin/mountpoint -q /sys/fs/bpf")
    );
    assert!(
        value(&d, "OnFailure").is_none(),
        "no failure handler unit ships in deploy/systemd"
    );
}

/// External audit ATP-014 (NN-AUD-262): both units set their search path,
/// without `/usr/local` — systemd's default for a service puts
/// `/usr/local/sbin:/usr/local/bin` first, and a binary planted there ran
/// in place of COMBAT's `iptables-restore`.
#[test]
fn both_units_set_a_path_without_usr_local() {
    for name in ["northnarrow-agent.service", "northnarrow-watchdog.service"] {
        let d = directives(&unit(name));
        let env: Vec<&str> = d
            .iter()
            .filter(|(k, _)| k == "Environment")
            .map(|(_, v)| v.as_str())
            .collect();
        let path = env
            .iter()
            .find_map(|v| v.strip_prefix("PATH="))
            .unwrap_or_else(|| panic!("{name}: no Environment=PATH= ({env:?})"));
        assert_eq!(path, "/usr/sbin:/usr/bin:/sbin:/bin", "{name}");
        assert!(
            path.split(':').all(|dir| !dir.starts_with("/usr/local")),
            "{name}: {path}"
        );
        assert!(
            value(&d, "EnvironmentFile").is_none(),
            "{name}: an EnvironmentFile could set PATH again"
        );
    }
}
