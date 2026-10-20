//! Lab verdict integrity (external audit Wave 3, lab PR 206: NN-AUD-410
//! LAB-020, NN-AUD-414 LAB-024, NN-AUD-416 LAB-026). What the lab reports
//! must be what it saw: `upgrade-check` wants the new agent's own health
//! line (all its deny hooks) and no degraded start in the signed chain, the
//! journal's state lines are read as events of the unit and process that
//! wrote them (never as text a file name can carry), the anti-tamper suite
//! runs only what `--only` names and lists every case it did not run, the
//! nightly runs the security checks and calls a check that does not apply
//! N/A, `help` prints the whole usage block, and every guest template takes
//! the lockdown argument. Offline: committed files, `bash` and `python3 -I`
//! only; no guest, nothing privileged, nothing written outside the target
//! directory.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const NN_LAB: &str = "deploy/lab/nn-lab.sh";
const ANTI_TAMPER: &str = "deploy/lab/adversarial/anti-tamper.sh";
const LAB_RECORDS: &str = "deploy/lab/lib/lab-records.py";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives one level below the repository root")
        .to_path_buf()
}

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The `# >>> name` … `# <<< name` block of a script.
fn block(rel: &str, name: &str) -> String {
    let text = read(rel);
    let start = text
        .find(&format!("# >>> {name}"))
        .unwrap_or_else(|| panic!("{rel}: no `# >>> {name}` block"));
    let end_marker = format!("# <<< {name}");
    let end = text[start..]
        .find(&end_marker)
        .map(|i| start + i + end_marker.len())
        .unwrap_or_else(|| panic!("{rel}: `{name}` block not closed"));
    text[start..end].to_string()
}

/// From the first `from` to the first `to` after it (`to` excluded).
fn section<'a>(text: &'a str, from: &str, to: &str) -> &'a str {
    let start = text.find(from).unwrap_or_else(|| panic!("no `{from}`"));
    let end = text[start..]
        .find(to)
        .map(|i| start + i)
        .unwrap_or_else(|| panic!("no `{to}` after `{from}`"));
    &text[start..end]
}

fn case_dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("lab-scripts")
        .join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// `bash -c "<script>"`, the environment of the test plus `env`.
fn bash(script: &str, env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("bash");
    cmd.arg("-c").arg(script).current_dir(repo_root());
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("bash runs")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// `python3 -I deploy/lab/lib/lab-records.py ARGS` with `input` on stdin.
fn lab_records(args: &[&str], input: &str) -> Output {
    let mut child = Command::new("python3")
        .arg("-I")
        .arg(repo_root().join(LAB_RECORDS))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("python3 runs (the lab helpers need it)");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

// ── nn-lab.sh help (LAB-026) ─────────────────────────────────────────────

/// `help` printed `sed -n '2,36p'` of a header that runs past line 60: the
/// sub-commands after `release-check` and every environment override were
/// cut. It prints the header comment up to its last line now.
#[test]
fn nn_lab_help_prints_the_whole_usage_block() {
    let text = read(NN_LAB);
    let want: Vec<String> = text
        .lines()
        .skip(1)
        .take_while(|l| l.starts_with('#'))
        .map(|l| {
            l.strip_prefix("# ")
                .or_else(|| l.strip_prefix('#'))
                .unwrap()
                .to_string()
        })
        .collect();
    assert!(
        want.iter().any(|l| l.contains("NN_LAB_NIGHTLY_SKIP"))
            && want.iter().any(|l| l.contains("NN_LAB_LOCKDOWN")),
        "the header documents the nightly skip list and the lockdown guest"
    );
    let home = case_dir("help");
    let lab = home.join("lab");
    let out = bash(
        &format!("unset NN_LAB_DISTRO NN_LAB_LOCKDOWN NN_LAB_ACCEL; exec bash {NN_LAB} help"),
        &[
            ("HOME", home.to_str().unwrap()),
            ("NN_LAB_DIR", lab.to_str().unwrap()),
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let got: Vec<String> = stdout(&out).lines().map(str::to_string).collect();
    assert_eq!(got, want);
}

/// NN_LAB_LOCKDOWN takes `integrity` (or nothing): any other value stops
/// the script before it touches a guest.
#[test]
fn nn_lab_refuses_an_unknown_lockdown_mode() {
    let home = case_dir("lockdown-mode");
    let lab = home.join("lab");
    let env = [
        ("HOME", home.to_str().unwrap()),
        ("NN_LAB_DIR", lab.to_str().unwrap()),
    ];
    for (mode, ok) in [
        ("integrity", true),
        ("", true),
        ("none", true),
        ("confidentiality", false),
        ("yes", false),
    ] {
        let out = bash(
            &format!("unset NN_LAB_DISTRO NN_LAB_ACCEL; NN_LAB_LOCKDOWN='{mode}' exec bash {NN_LAB} help"),
            &env,
        );
        assert_eq!(out.status.success(), ok, "NN_LAB_LOCKDOWN={mode:?}");
        if !ok {
            assert_eq!(out.status.code(), Some(2), "NN_LAB_LOCKDOWN={mode:?}");
            assert!(String::from_utf8_lossy(&out.stderr).contains("unknown NN_LAB_LOCKDOWN"));
        }
    }
}

// ── the guest templates (LAB-024) ────────────────────────────────────────

fn templates() -> Vec<PathBuf> {
    let dir = repo_root().join("deploy/lab");
    let mut t: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.expect("readable directory entry").path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("user-data") && n.ends_with(".tmpl"))
        })
        .collect();
    t.sort();
    assert!(t.len() >= 4, "{t:?}");
    t
}

/// No template set `lockdown=`, so C27 never ran. Each one now ends its
/// lsm= line with the placeholder `render_user_data` fills: nothing on a
/// guest, ` lockdown=integrity` on the NN_LAB_LOCKDOWN one; a template
/// without it is refused rather than booting an unlocked "lockdown" guest.
#[test]
fn every_guest_template_takes_the_lockdown_argument() {
    let render = block(NN_LAB, "render-user-data");
    let dir = case_dir("render");
    fs::write(dir.join("key.pub"), "ssh-ed25519 AAAAtest nn-lab\n").unwrap();
    for t in templates() {
        let text = fs::read_to_string(&t).unwrap();
        let lines: Vec<&str> = text
            .lines()
            .filter(|l| l.contains("__NN_LAB_KARGS__"))
            .collect();
        assert_eq!(lines.len(), 1, "{}: {lines:?}", t.display());
        assert!(
            lines[0].contains("lsm=") && lines[0].ends_with("bpf__NN_LAB_KARGS__\""),
            "{}: {}",
            t.display(),
            lines[0]
        );
        for (lockdown, tail) in [("", "bpf\""), ("integrity", "bpf lockdown=integrity\"")] {
            let out_file = dir.join("user-data");
            let script = format!(
                "set -euo pipefail\ndie() {{ echo \"die: $*\" >&2; exit 1; }}\n{render}\n\
                 KEY={key}; USER_DATA_TMPL={tmpl}; LOCKDOWN='{lockdown}'\n\
                 render_user_data {out}\n",
                key = dir.join("key").display(),
                tmpl = t.display(),
                out = out_file.display(),
            );
            let out = bash(&script, &[]);
            assert!(
                out.status.success(),
                "{} ({lockdown:?}): {}",
                t.display(),
                String::from_utf8_lossy(&out.stderr)
            );
            let rendered = fs::read_to_string(&out_file).unwrap();
            assert!(
                !rendered.contains("__"),
                "{}: placeholder left",
                t.display()
            );
            assert!(rendered.contains("ssh-ed25519 AAAAtest nn-lab"));
            let lsm: Vec<&str> = rendered
                .lines()
                .filter(|l| l.contains("lsm=lockdown,"))
                .collect();
            assert_eq!(lsm.len(), 1, "{}", t.display());
            assert!(
                lsm[0].ends_with(tail),
                "{} ({lockdown:?}): {}",
                t.display(),
                lsm[0]
            );
        }
    }
    // a template without the placeholder
    let bare = dir.join("bare.tmpl");
    fs::write(
        &bare,
        "#cloud-config\nruncmd:\n  - grubby --args=\"lsm=bpf\"\n",
    )
    .unwrap();
    let script = format!(
        "set -euo pipefail\ndie() {{ echo \"die: $*\" >&2; exit 1; }}\n{render}\n\
         KEY={key}; USER_DATA_TMPL={bare}; LOCKDOWN=integrity\nrender_user_data {out}\n",
        key = dir.join("key").display(),
        bare = bare.display(),
        out = dir.join("bare-out").display(),
    );
    let out = bash(&script, &[]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no __NN_LAB_KARGS__"));
}

// ── the nightly (LAB-026) ────────────────────────────────────────────────

/// The nightly ran none of the security checks. They run now on the fresh
/// install (after `install`, before the steps that replace or remove it),
/// and each one has its arm in the step runner.
#[test]
fn the_nightly_runs_the_security_checks() {
    let text = read(NN_LAB);
    let value = |name: &str| -> String {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{name}=\"")))
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or_else(|| panic!("{NN_LAB}: no {name}=\"…\""))
            .to_string()
    };
    let security = value("NIGHTLY_SECURITY_STEPS");
    let sec: Vec<&str> = security.split_whitespace().collect();
    for s in [
        "tamper-check",
        "pkgmgr-check",
        "open-sensor-check",
        "fim-reuse-check",
        "btrfs-check",
        "overlay-check",
    ] {
        assert!(sec.contains(&s), "{s} is not a nightly step: {sec:?}");
    }
    let all = value("NIGHTLY_STEPS").replace("$NIGHTLY_SECURITY_STEPS", &security);
    let steps: Vec<&str> = all.split_whitespace().collect();
    let pos = |s: &str| {
        steps
            .iter()
            .position(|x| *x == s)
            .unwrap_or_else(|| panic!("{s} not in {steps:?}"))
    };
    for s in &sec {
        assert!(
            pos("install") < pos(s) && pos(s) < pos("respawn-check"),
            "{s} must run on the fresh install: {steps:?}"
        );
    }
    let runner = section(&text, "nightly_run_step() {", "\n}\n");
    for s in &steps {
        assert!(
            runner
                .lines()
                .any(|l| l.trim_start().starts_with(&format!("{s})"))),
            "nightly_run_step has no `{s})` arm"
        );
    }
}

/// A step's status: exit 0 is "ok" only for a step that ran — a check that
/// reports itself not applicable (btrfs-check on a kernel without btrfs,
/// exit 0) is N/A, and a NOT RUN fails whatever its exit status.
#[test]
fn a_nightly_step_that_did_not_run_is_not_ok() {
    let status = block(NN_LAB, "nightly-status");
    let dir = case_dir("nightly-status");
    let cases: [(&str, &str, &str); 6] = [
        ("0", "ok    a\nbtrfs-check: PASS — x\n", "✅ ok"),
        (
            "0",
            "btrfs-check: N/A — this kernel has no btrfs (RHEL 9 does not ship it)\n",
            "➖ btrfs-check: N/A — this kernel has no btrfs (RHEL 9 does not ship it)",
        ),
        (
            "2",
            "btrfs-check: NOT RUN — the btrfs module exists but did not load\n",
            "❌ not run (rc=2)",
        ),
        (
            "0",
            "NOT RUN  inode 5 not reused within 5000 files\n",
            "❌ not run (rc=0)",
        ),
        ("1", "FAIL  x\n", "❌ rc=1"),
        ("-1", "", "⏭ skipped"),
    ];
    for (i, (rc, log, want)) in cases.iter().enumerate() {
        let file = dir.join(format!("{i}.log"));
        fs::write(&file, log).unwrap();
        // under the script's own options
        let out = bash(
            &format!(
                "set -euo pipefail\n{status}\nnightly_status '{rc}' '{}'",
                file.display()
            ),
            &[],
        );
        assert_eq!(stdout(&out).trim_end(), *want, "rc {rc}, log {log:?}");
    }
    // a step whose log is missing (skipped steps have none)
    let out = bash(
        &format!("set -euo pipefail\n{status}\nnightly_status -1 /nonexistent"),
        &[],
    );
    assert_eq!(stdout(&out).trim_end(), "⏭ skipped");
}

// ── upgrade-check (LAB-020) ──────────────────────────────────────────────

/// upgrade-check passed with seven of the agent's LSM programs, against 16
/// deny hooks plus the observers. It wants the new agent's health line
/// with every deny hook — at least DENY_HOOKS of the agent — no fewer own
/// programs than before, and no anti-tamper `subsystem_degraded` signed
/// at the upgraded boot.
#[test]
fn upgrade_check_wants_every_deny_hook_of_the_agent() {
    let lab = read(NN_LAB);
    let upgrade = section(&lab, "cmd_upgrade_check() {", "\ncmd_uninstall_check() {");
    let min: usize = upgrade
        .lines()
        .find_map(|l| l.trim().strip_prefix("deny_hooks_min="))
        .expect("upgrade-check sets deny_hooks_min")
        .parse()
        .unwrap();
    let agent = read("agent/src/anti_tamper/mod.rs");
    let n: usize = agent
        .lines()
        .find_map(|l| l.trim().strip_prefix("pub const DENY_HOOKS: [&str; "))
        .and_then(|r| r.split(']').next())
        .expect("DENY_HOOKS is a fixed-size array")
        .parse()
        .unwrap();
    assert_eq!(min, n, "upgrade-check's floor is DENY_HOOKS.len()");
    // the agent's message, read as one of its own events
    assert!(agent.contains("deny_expected, \"anti-tamper: all LSM hooks attached\""));
    assert!(upgrade.contains(
        "lab-records.py journal northnarrow-agent.service \"$pid_after\" INFO \"anti-tamper: all LSM hooks attached \""
    ));
    assert!(upgrade.contains("lab-records.py degraded"));
    assert!(upgrade.contains("(( n < n_before ))"));
    assert!(!upgrade.contains("n >= 7"), "the old floor is gone");
}

/// The journal state lines the lab reads — the health line, the BPF guard
/// mode, the trusted-installer window, the drop-in registration, the
/// watchdog's registration — were grepped anywhere in a line, and any user
/// can make the agent log a file name holding them. Every read now goes
/// through the helper (`jentry`, `agent_event`, `lab-records.py`), or
/// matches its output from the start (`'^…`).
#[test]
fn no_lab_verdict_greps_journal_text_for_an_agent_line() {
    const PHRASES: [&str; 6] = [
        "all LSM hooks attached",
        "watchdog PID registered",
        "own objects registered",
        "trusted-installer override",
        "registered in PROTECTED_INODES",
        "binary integrity verified",
    ];
    const THROUGH: [&str; 4] = ["jentry ", "agent_event ", "lab-records.py", "'^"];
    let mut bad = Vec::new();
    for rel in [NN_LAB, ANTI_TAMPER, "deploy/lab/release/release-check.sh"] {
        let mut text = read(rel);
        // the anti-tamper self-test feeds such lines to the helpers
        if let Some(start) = text.find("\nselftest() {") {
            let end = start + text[start..].find("\n}\n").expect("selftest() ends");
            text.replace_range(start..end, "");
        }
        for (i, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with('#') || !PHRASES.iter().any(|p| code.contains(p)) {
                continue;
            }
            if !THROUGH.iter().any(|t| code.contains(t)) {
                bad.push(format!("{rel}:{}: {code}", i + 1));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "journal text read as a verdict:\n{}",
        bad.join("\n")
    );
}

fn agent_entry(pid: &str, message: &str) -> String {
    serde_json::json!({
        "_SYSTEMD_UNIT": "northnarrow-agent.service",
        "_TRANSPORT": "stdout",
        "_PID": pid,
        "MESSAGE": message,
    })
    .to_string()
}

/// The helper's own cases, and the forged health line through its command
/// line: a file named like the line, run by another user, appears in the
/// new agent's VERDICT line — from the agent's own unit and pid — and is
/// not the line.
#[test]
fn a_file_named_like_the_health_line_is_not_the_health_line() {
    let out = lab_records(&["--selftest"], "");
    assert!(
        out.status.success(),
        "{}{}",
        stdout(&out),
        String::from_utf8_lossy(&out.stderr)
    );
    let ts = "2026-10-20T10:00:00.123456Z";
    let health = "anti-tamper: all LSM hooks attached deny_attached=18 deny_expected=18";
    let forged = [
        agent_entry(
            "4242",
            &format!(
                "{ts}  INFO VERDICT (rule) rule=R001_ExecFromTmp target_filename=\"/tmp/x\\n{ts}  INFO {health}\""
            ),
        ),
        agent_entry(
            "4242",
            &format!("{ts}  WARN x target_filename=\"/tmp/{health}\""),
        ),
        // the real line, from another process
        agent_entry("777", &format!("{ts}  INFO {health}")),
    ]
    .join("\n")
        + "\n";
    let args = [
        "journal",
        "northnarrow-agent.service",
        "4242",
        "INFO",
        "anti-tamper: all LSM hooks attached ",
    ];
    let out = lab_records(&args, &forged);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert_eq!(stdout(&out), "");
    let real = forged.clone() + &agent_entry("4242", &format!("{ts}  INFO {health}")) + "\n";
    let out = lab_records(&args, &real);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), format!("{health}\n"));
}

// ── anti-tamper.sh --only (LAB-026) ──────────────────────────────────────

/// `--only` without a value ran every case, the destructive ones too. A
/// value that is not a list of case ids stops the script before anything
/// else (an empty PATH: even a regression would find no tool to run).
#[test]
fn anti_tamper_only_takes_case_ids() {
    let script = repo_root().join(ANTI_TAMPER);
    for args in [
        vec!["--only"],
        vec!["--only", ""],
        vec!["--only", "C1"],
        vec!["--only", "C01,"],
        vec!["--only", "C01 C02"],
        vec!["--only", "--persistence"],
    ] {
        let out = Command::new("/bin/bash")
            .arg(&script)
            .args(&args)
            .env_clear()
            .env("PATH", "")
            .output()
            .expect("bash runs");
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("--only takes case ids"),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// A case that cannot run is a row only for a run that selects it (`--only
/// C01` failed on a probe another case needs), and an `--only` id no row
/// names — a typo, a case a condition skipped — fails the run instead of
/// reading OK.
#[test]
fn anti_tamper_reports_what_only_asked_for() {
    let sel = block(ANTI_TAMPER, "case-selection");
    let run = |only: &str, body: &str| {
        let out = bash(
            &format!(
                "set -u\nrows=(); fail=0; ONLY='{only}'\n{sel}\n{body}\n\
                 printf 'fail=%s\\n' \"$fail\"; for r in ${{rows[@]+\"${{rows[@]}}\"}}; do printf '%s\\n' \"$r\"; done"
            ),
            &[],
        );
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        stdout(&out)
    };
    assert_eq!(
        run("C01", "skipped_case C34,C35,C43 'no probe' 0 2>/dev/null"),
        "fail=0\n"
    );
    assert_eq!(
        run("C43", "skipped_case C34,C35,C43 'no probe' 0 2>/dev/null"),
        "fail=1\n| C34,C35,C43 | (not run) | SKIPPED (no probe) | — | DEVIATION (not run: no probe) |\n"
    );
    assert_eq!(
        run("", "skipped_case C22 'io_uring_disabled=2' 1 2>/dev/null"),
        "fail=0\n| C22 | (not run) | SKIPPED (io_uring_disabled=2) | — | N/A (io_uring_disabled=2) |\n"
    );
    assert_eq!(
        run(
            "C01,C99",
            "rows+=('| C01 | kill | denied | e | OK |'); report_unreported 2>/dev/null"
        ),
        "fail=1\n| C01 | kill | denied | e | OK |\n\
         | C99 | (not run) | no such case, or it did not run | — | DEVIATION (--only C99: no row) |\n"
    );
    assert_eq!(
        run(
            "C55",
            "rows+=('| C55a | SIGSTOP | denied | e | OK |'); report_unreported 2>/dev/null"
        ),
        "fail=1\n| C55a | SIGSTOP | denied | e | OK |\n\
         | C55 | (not run) | no such case, or it did not run | — | DEVIATION (--only C55: no row) |\n"
    );
    assert_eq!(run("", "report_unreported"), "fail=0\n");
}
