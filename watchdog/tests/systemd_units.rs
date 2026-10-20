//! Regression guard for the respawn-v2 unit contract
//! (docs/design/WATCHDOG_RESPAWN_V2_DESIGN.md §4): parses the shipped
//! unit files so a well-meaning edit cannot silently re-introduce
//! `BindsTo=` (watchdog stopped on agent crash) or re-enable systemd's
//! start-rate limiter / auto-restart on the agent unit. Also the package
//! hooks that start the units again after a failed package operation
//! (external audit DEP-010), run against stub `systemctl`.

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
/// (the agent is not dumpable). External audit DEP-014 (NN-AUD-386): and
/// it has nothing else but CAP_BPF — no CAP_SYS_ADMIN, which nothing it
/// does needs.
#[test]
fn watchdog_unit_can_verify_the_agents_executable() {
    let d = directives(&unit("northnarrow-watchdog.service"));
    let caps = value(&d, "CapabilityBoundingSet").expect("bounding set");
    assert!(
        caps.split_whitespace().any(|c| c == "CAP_SYS_PTRACE"),
        "{caps}"
    );
    let mut set: Vec<&str> = caps.split_whitespace().collect();
    set.sort_unstable();
    assert_eq!(set, ["CAP_BPF", "CAP_SYS_PTRACE"], "{caps}");
    assert_eq!(
        d.iter()
            .filter(|(k, _)| k == "CapabilityBoundingSet" || k == "AmbientCapabilities")
            .count(),
        1,
        "one bounding set, no ambient capabilities"
    );
}

/// External audit DEP-017 (NN-AUD-389): journald's default rate limit
/// (10000 lines per 30 s) dropped the rest of an agent burst, chain-head
/// lines included. The agent's unit raises it — bounded, not 0 — and the
/// namespace's config leaves it to the units.
#[test]
fn agent_unit_raises_its_journal_rate_limit() {
    let d = directives(&unit("northnarrow-agent.service"));
    assert_eq!(value(&d, "LogRateLimitIntervalSec"), Some("30s"));
    let burst: u64 = value(&d, "LogRateLimitBurst")
        .expect("LogRateLimitBurst")
        .parse()
        .expect("a number of lines");
    assert!(
        burst > 10_000 && burst <= 100_000,
        "above journald's default, still bounded (0 is no limit): {burst}"
    );
    let w = directives(&unit("northnarrow-watchdog.service"));
    assert!(value(&w, "LogRateLimitBurst").is_none_or(|b| b != "0"));
    let ns = directives(&unit("journald@northnarrow.conf"));
    for key in ["RateLimitBurst", "RateLimitIntervalSec", "Seal"] {
        assert!(
            value(&ns, key).is_none(),
            "{key} belongs to the units / the default"
        );
    }
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

// ── package hooks: the rollback restart (external audit DEP-010) ──────

fn pkg_hook(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("deploy/release/pkg")
        .join(name)
}

fn restart_block(hook: &str) -> String {
    let p = pkg_hook(hook);
    let body =
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()));
    let start = body
        .find("# >>> restart_stopped")
        .unwrap_or_else(|| panic!("{hook}: no restart_stopped block"));
    let end = body
        .find("# <<< restart_stopped")
        .unwrap_or_else(|| panic!("{hook}: restart_stopped block not closed"));
    body[start..end].to_string()
}

/// External audit DEP-010 (NN-AUD-382): the post-unpack hook (deb
/// `abort-upgrade`, `abort-remove`, `abort-deconfigure`) and the
/// post-removal hook (`abort-install`, `abort-upgrade`) restart the same
/// way; one copy cannot keep the old `|| true` behind the other's fix.
#[test]
fn package_hooks_share_one_rollback_restart() {
    let a = restart_block("postinst.sh");
    assert_eq!(a, restart_block("postrm.sh"));
    assert!(a.contains("systemctl is-active"), "{a}");
    for hook in ["postinst.sh", "postrm.sh"] {
        let p = pkg_hook(hook);
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(
            body.contains("restart_stopped || exit 1"),
            "{hook}: a failed restart must fail the hook"
        );
    }
}

/// One rollback run of `hook arg` against stub `systemctl`, `logger` and
/// `sleep`: `listed` the restart list, `down` the units whose start fails.
struct Rollback {
    status: Option<i32>,
    stderr: String,
    calls: Vec<String>,
    logged: String,
    list_kept: bool,
}

fn rollback(hook: &str, arg: &str, listed: Option<&[&str]>, down: &[&str]) -> Rollback {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let stub = |name: &str, body: &str| {
        let p = bin.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    stub(
        "systemctl",
        r#"echo "$*" >> "$NN_TEST_DIR/calls"
case "$1" in
    start) [ ! -e "$NN_TEST_DIR/down.$2" ] ;;
    is-active) if [ -e "$NN_TEST_DIR/down.$2" ]; then echo failed; exit 3; fi; echo active ;;
    *) exit 1 ;;
esac"#,
    );
    stub("logger", r#"echo "$*" >> "$NN_TEST_DIR/logged""#);
    stub("sleep", "exit 0");
    for u in down {
        std::fs::write(dir.path().join(format!("down.{u}.service")), "").unwrap();
    }
    let list = dir.path().join("pkg-restart");
    if let Some(units) = listed {
        std::fs::write(
            &list,
            units.iter().map(|u| format!("{u}\n")).collect::<String>(),
        )
        .unwrap();
    }
    let out = std::process::Command::new("sh")
        .arg(pkg_hook(hook))
        .arg(arg)
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("NN_TEST_DIR", dir.path())
        .env("PKG_RESTART_FILE", &list)
        .output()
        .expect("sh runs");
    let read = |name: &str| std::fs::read_to_string(dir.path().join(name)).unwrap_or_default();
    Rollback {
        status: out.status.code(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        calls: read("calls").lines().map(str::to_string).collect(),
        logged: read("logged"),
        list_kept: list.exists(),
    }
}

const ROLLBACKS: [(&str, &str); 5] = [
    ("postinst.sh", "abort-upgrade"),
    ("postinst.sh", "abort-remove"),
    ("postinst.sh", "abort-deconfigure"),
    ("postrm.sh", "abort-upgrade"),
    ("postrm.sh", "abort-install"),
];
const BOTH: &[&str] = &["northnarrow-agent", "northnarrow-watchdog"];

/// External audit DEP-010 (NN-AUD-382): a unit that does not come back
/// after the rollback fails the hook — the package manager reports the
/// rollback as failed — and is named on stderr and at auth.err. Before,
/// every start was `|| true` and the hook exited 0 with the agent down.
#[test]
fn a_rollback_that_leaves_a_unit_down_fails_and_names_it() {
    for (hook, arg) in ROLLBACKS {
        let r = rollback(hook, arg, Some(BOTH), &["northnarrow-agent"]);
        assert_eq!(r.status, Some(1), "{hook} {arg}: {}", r.stderr);
        assert!(
            r.stderr.contains("northnarrow-agent.service (failed)")
                && r.stderr.contains("without NorthNarrow"),
            "{hook} {arg}: {}",
            r.stderr
        );
        assert!(
            !r.stderr.contains("northnarrow-watchdog.service ("),
            "{hook} {arg}: the watchdog came back: {}",
            r.stderr
        );
        assert!(
            r.logged.starts_with("-p auth.err -t northnarrow-pkg -- ")
                && r.logged.contains("northnarrow-agent.service (failed)"),
            "{hook} {arg}: {:?}",
            r.logged
        );
        assert!(
            r.list_kept,
            "{hook} {arg}: the list stays for the next attempt"
        );
        // the watchdog is still started after a failed agent
        assert_eq!(
            &r.calls[..2],
            [
                "start northnarrow-agent.service",
                "start northnarrow-watchdog.service"
            ],
            "{hook} {arg}"
        );
    }
}

/// The rollback that brings every listed unit back succeeds quietly,
/// agent first, and drops the list; nothing listed starts nothing.
#[test]
fn a_rollback_that_brings_the_units_back_succeeds() {
    for (hook, arg) in ROLLBACKS {
        let r = rollback(hook, arg, Some(BOTH), &[]);
        assert_eq!(r.status, Some(0), "{hook} {arg}: {}", r.stderr);
        assert!(r.stderr.is_empty() && r.logged.is_empty(), "{hook} {arg}");
        assert!(!r.list_kept, "{hook} {arg}");
        assert_eq!(
            r.calls,
            [
                "start northnarrow-agent.service",
                "start northnarrow-watchdog.service",
                "is-active northnarrow-agent.service",
                "is-active northnarrow-watchdog.service",
            ],
            "{hook} {arg}"
        );

        let only = rollback(hook, arg, Some(&["northnarrow-agent"]), &[]);
        assert_eq!(only.status, Some(0), "{hook} {arg}");
        assert_eq!(
            only.calls,
            [
                "start northnarrow-agent.service",
                "is-active northnarrow-agent.service"
            ],
            "{hook} {arg}: only what the pre-unpack hook stopped"
        );

        let none = rollback(hook, arg, None, &["northnarrow-agent"]);
        assert_eq!(none.status, Some(0), "{hook} {arg}");
        assert!(none.calls.is_empty(), "{hook} {arg}: {:?}", none.calls);
    }
}
