//! `deploy/install.sh` and `deploy/uninstall.sh` (external audit, Wave 3,
//! lab PR 194: DEP-016 NN-AUD-388, DEP-020 NN-AUD-440, DEP-012 NN-AUD-384).
//! The scripts refuse to run without root, so each test runs one part of
//! them under `bash`: a function block between its `# >>> name` and
//! `# <<< name` markers, or the stop section of a script with stub
//! `systemctl`, `rm`, `bpftool`, `sleep` and installed binaries first on
//! PATH and the pin root in a temporary directory. A stub `rm` refuses the
//! pin root until the stub `nn-admin` has opened the trusted-installer
//! window, as the anti-tamper does.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

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

/// The text between `# >>> name` and `# <<< name`, both markers included.
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
fn section(rel: &str, from: &str, to: &str) -> String {
    let text = read(rel);
    let start = text
        .find(from)
        .unwrap_or_else(|| panic!("{rel}: no `{from}`"));
    let end = text[start..]
        .find(to)
        .map(|i| start + i)
        .unwrap_or_else(|| panic!("{rel}: no `{to}` after `{from}`"));
    text[start..end].to_string()
}

/// A fresh directory for one case.
fn case_dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("install-scripts")
        .join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_exec(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

// ── DEP-016: SHA256SUMS lookup by name ───────────────────────────────────

/// `sums_expected NAME FILE` from install.sh: (exit status, stdout).
fn sums_expected(case: &str, sums: Option<&str>, name: &str) -> (i32, String) {
    let dir = case_dir(case);
    let file = dir.join("SHA256SUMS");
    if let Some(s) = sums {
        fs::write(&file, s).unwrap();
    }
    let script = format!(
        "set -euo pipefail\n{}\nsums_expected \"$1\" \"$2\"\n",
        block("deploy/install.sh", "sums_expected")
    );
    let out = Command::new("bash")
        .arg("-c")
        .arg(script)
        .arg("bash")
        .arg(name)
        .arg(&file)
        .output()
        .expect("bash runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
    )
}

/// External audit DEP-016 (NN-AUD-388): the tarball's name was a `grep -E`
/// pattern. Its dots matched any character, so the line of another file
/// listed first was taken for it (a spurious REFUSED), and a name with a
/// `+` was never found. It is compared as a string now, the binary-mode `*`
/// removed; two different checksums for one name are refused.
#[test]
fn sums_expected_matches_the_name_as_a_string() {
    let (a, b, c, d, e) = (
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(64),
        "d".repeat(64),
        "e".repeat(64),
    );
    let sums = format!(
        "{a}  northnarrow-1X2.3-x86_64-linux.tar.gz\n\
         {b}  northnarrow-1.2.3-x86_64-linux.tar.gz\n\
         {c} *northnarrow-1.2.3+lab-x86_64-linux.tar.gz\n\
         {d}  northnarrow-1.2.3-x86_64-linux.tar.gz.sbom.cdx.json\n\
         {e}  old/northnarrow-0.9-x86_64-linux.tar.gz\n"
    );
    let found = |case: &str, name: &str| sums_expected(case, Some(&sums), name);
    assert_eq!(
        found("exact", "northnarrow-1.2.3-x86_64-linux.tar.gz"),
        (0, b.clone()),
        "the line of `…-1X2.3-…`, listed first, must not be taken for `…-1.2.3-…`"
    );
    assert_eq!(
        found("plus-binary", "northnarrow-1.2.3+lab-x86_64-linux.tar.gz"),
        (0, c),
        "a `+` in the name, a `*` before it"
    );
    for (case, name) in [
        ("prefix", "northnarrow-1.2.3"),
        ("path", "northnarrow-0.9-x86_64-linux.tar.gz"),
        ("pattern", ".*"),
        ("pattern2", "northnarrow-1.2.3-x86_64-linux.tar.gz.*"),
    ] {
        assert_eq!(found(case, name), (1, String::new()), "{case}: {name}");
    }

    let twice_same = format!("{b}  n.tar.gz\n{}  n.tar.gz\n", b.to_uppercase());
    assert_eq!(
        sums_expected("twice-same", Some(&twice_same), "n.tar.gz"),
        (0, b.clone()),
        "the same checksum twice (any case) is one checksum"
    );
    let twice_diff = format!("{b}  n.tar.gz\n{e}  n.tar.gz\n");
    assert_eq!(
        sums_expected("twice-different", Some(&twice_diff), "n.tar.gz"),
        (3, String::new()),
        "two different checksums for one name: refused, not the first"
    );
    let (rc, out) = sums_expected("missing-file", None, "n.tar.gz");
    assert!(
        rc != 0 && rc != 1 && rc != 3 && out.is_empty(),
        "{rc} {out}"
    );
}

/// verify_release takes the checksum from `sums_expected` and names each
/// refusal; the pattern lookup is gone.
#[test]
fn verify_release_uses_the_string_lookup() {
    let verify = section(
        "deploy/install.sh",
        "verify_release() {",
        "\nrequire_provenance_floor() {",
    );
    assert!(
        verify.contains("expected=$(sums_expected \"$(basename \"$tgz\")\" \"$sums\") || rc=$?"),
        "{verify}"
    );
    assert!(!verify.contains("grep -E"), "{verify}");
    for refusal in [
        "is not listed in",
        "more than once, with different checksums",
        "could not be read",
    ] {
        assert!(verify.contains(refusal), "{refusal}");
    }
}

// ── DEP-020: stale pins with both units stopped ─────────────────────────

/// External audit DEP-020 (NN-AUD-440): install.sh and uninstall.sh start
/// the installed agent for the window the same way.
#[test]
fn both_scripts_share_the_stale_pin_root_block() {
    let a = block("deploy/install.sh", "stale_pin_root");
    assert_eq!(a, block("deploy/uninstall.sh", "stale_pin_root"));
    assert!(
        a.contains("systemctl start northnarrow-agent.service"),
        "{a}"
    );
    assert!(!a.contains("northnarrow-watchdog.service"), "{a}");
    for (rel, me) in [
        ("deploy/install.sh", "install.sh"),
        ("deploy/uninstall.sh", "uninstall.sh"),
    ] {
        let text = read(rel);
        let set = text
            .find(&format!("NN_SELF={me}\n"))
            .unwrap_or_else(|| panic!("{rel}: NN_SELF={me}"));
        assert!(set < text.find("# >>> stale_pin_root").unwrap(), "{rel}");
    }
}

/// The host a stop section runs against: unit states, the pin root, the
/// key, and what the stubs saw.
/// The fake admin socket of a test host: a unix socket path must stay
/// under SUN_LEN (108 bytes), and CARGO_TARGET_TMPDIR on a CI runner is
/// already longer than that once a case directory is added — so the
/// socket lives in the system temp directory, named from the case's.
fn admin_socket_path(dir: &Path) -> PathBuf {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    dir.hash(&mut h);
    std::env::temp_dir().join(format!("nn194-{:016x}.sock", h.finish()))
}

struct Host {
    dir: PathBuf,
}

#[derive(Debug)]
struct Run {
    status: i32,
    stdout: String,
    stderr: String,
    calls: Vec<String>,
}

impl Run {
    fn called(&self, what: &str) -> usize {
        self.calls.iter().filter(|c| c.as_str() == what).count()
    }
    fn index(&self, what: &str) -> Option<usize> {
        self.calls.iter().position(|c| c.as_str() == what)
    }
}

impl Host {
    /// `running`: the units active (with a process in their cgroup);
    /// `pins`: a pin root left; `protected`: no window open yet.
    fn new(case: &str, running: &[&str], pins: bool, protected: bool) -> Host {
        let dir = case_dir(case);
        let stub = dir.join("stub");
        let bin = dir.join("bin");
        fs::create_dir_all(&stub).unwrap();
        fs::create_dir_all(&bin).unwrap();
        for u in ["northnarrow-agent", "northnarrow-watchdog"] {
            let cg = dir.join("cg").join(u);
            fs::create_dir_all(&cg).unwrap();
            let up = running.contains(&u);
            fs::write(
                dir.join(format!("state.{u}")),
                if up { "active\n" } else { "inactive\n" },
            )
            .unwrap();
            fs::write(cg.join("cgroup.procs"), if up { "4242\n" } else { "" }).unwrap();
        }
        if pins {
            fs::create_dir_all(dir.join("pins/maps")).unwrap();
            fs::write(dir.join("pins/maps/PROTECTED_PIDS"), "").unwrap();
        }
        if !protected {
            fs::write(dir.join("window"), "").unwrap();
        }
        fs::write(dir.join("own-ids"), "17\n").unwrap();
        fs::write(dir.join("key-role"), "trusted-installer\n").unwrap();
        fs::write(dir.join("key-norole"), "config-manage\n").unwrap();
        // systemctl: unit states in $T/state.<unit>, processes in
        // $T/cg/<unit>/cgroup.procs (ControlGroup points there through
        // /sys/fs/cgroup/../../..); a signal is delivered only inside the
        // window, as with the agent's PID-1 grant.
        write_exec(
            &stub.join("systemctl"),
            r#"T=$NN_TEST_DIR
echo "systemctl $*" >> "$T/calls"
cmd=$1; shift
q=; if [ "${1:-}" = --quiet ]; then q=1; shift; fi
case "$cmd" in
    is-active)
        u=${1%.service}; st=$(cat "$T/state.$u" 2>/dev/null || echo inactive)
        [ -n "$q" ] || echo "$st"
        [ "$st" = active ] ;;
    start)
        u=${1%.service}
        [ -e "$T/start-fails" ] && exit 1
        echo active > "$T/state.$u"; echo 4242 > "$T/cg/$u/cgroup.procs" ;;
    kill)
        u=${2%.service}
        [ -e "$T/window" ] || exit 1
        echo inactive > "$T/state.$u"; : > "$T/cg/$u/cgroup.procs" ;;
    show)
        u=${4%.service}; echo "/../../..$T/cg/$u" ;;
    *) exit 0 ;;
esac"#,
        );
        write_exec(
            &stub.join("rm"),
            r#"for a in "$@"; do
    case "$a" in
        "$NN_TEST_DIR"/pins*)
            if [ ! -e "$NN_TEST_DIR/window" ]; then
                echo "rm: cannot remove '$a': Operation not permitted" >&2; exit 1
            fi ;;
    esac
done
exec /bin/rm "$@""#,
        );
        write_exec(
            &stub.join("bpftool"),
            r#"if [ "$2" = show ] && [ "${3:-}" = id ]; then
    echo "Error: get by id ($4): No such file or directory" >&2; exit 255
fi
exit 0"#,
        );
        write_exec(&stub.join("sleep"), "exit 0");
        write_exec(
            &bin.join("nn-admin"),
            r#"echo "nn-admin $1" >> "$NN_TEST_DIR/calls"
if [ "$1" = trusted-installer-grant ]; then
    grep -q trusted-installer "$3" || exit 1
    : > "$NN_TEST_DIR/window"
fi
exit 0"#,
        );
        write_exec(
            &bin.join("northnarrow-agent"),
            "echo 'northnarrow-agent 0.0.1'",
        );
        Host { dir }
    }

    fn socket(&self) -> std::os::unix::net::UnixListener {
        let path = admin_socket_path(&self.dir);
        let _ = std::fs::remove_file(&path);
        std::os::unix::net::UnixListener::bind(path).unwrap()
    }

    fn pins_left(&self) -> bool {
        self.dir.join("pins").exists()
    }

    fn run(&self, prelude: &str, body: &str) -> Run {
        let t = &self.dir;
        let script = format!(
            "set -euo pipefail\nT='{t}'\n{prelude}\n{body}\necho \"RESULT ok\"\n",
            t = t.display()
        );
        let path = format!(
            "{}:{}",
            t.join("stub").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let out = Command::new("bash")
            .arg("-c")
            .arg(script)
            .env("PATH", path)
            .env("NN_TEST_DIR", t)
            .env("OWN_IDS_FILE", t.join("own-ids"))
            .env("LSM_DRAIN_TIMEOUT", "2")
            .env("ADMIN_SOCKET", admin_socket_path(t))
            .env("ADMIN_SOCKET_WAIT", "2")
            .output()
            .expect("bash runs");
        let calls = fs::read_to_string(t.join("calls"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect();
        Run {
            status: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
            calls,
        }
    }

    /// install.sh from its unit stop to the end of the running-install
    /// part, with `mode` (full, stop) and `--upgrade`/`--grant-key`.
    fn install(&self, mode: &str, upgrade: bool, key: Option<&str>) -> Run {
        let body = section(
            "deploy/install.sh",
            "stop_nn_unit() {",
            "if [[ $MODE == stop ]]; then\n    # $PKG_RESTART_FILE hands",
        );
        let prelude = format!(
            "MODE={mode}; UPGRADE={}; GRANT_KEY={}\n\
             BIN_DIR=$T/bin; AGENT_BIN=$T/bin/northnarrow-agent\n\
             PKG_RESTART_FILE=$T/pkg-restart; BPFFS_ROOT=$T/pins",
            u8::from(upgrade),
            key.map(|k| format!("$T/{k}")).unwrap_or_default(),
        );
        let after = "echo \"RESULT restart=[${UNITS_TO_RESTART[*]:-}]\"";
        self.run(&prelude, &format!("{body}\n{after}"))
    }

    /// uninstall.sh from `log()` to its step 2 (the pin root's removal).
    fn uninstall(&self, package: bool, key: Option<&str>) -> Run {
        let body = section("deploy/uninstall.sh", "log() {", "# ── 2. LSM programs");
        let prelude = format!(
            "PURGE=0; YES=1; PACKAGE={}; GRANT_KEY={}\n\
             BIN_DIR=$T/bin; UNIT_DIR=$T/units; ETC_DIR=$T/etc; STATE_DIR=$T/state; BPFFS_ROOT=$T/pins",
            u8::from(package),
            key.map(|k| format!("$T/{k}")).unwrap_or_default(),
        );
        self.run(&prelude, &body)
    }
}

const START_AGENT: &str = "systemctl start northnarrow-agent.service";
const START_WATCHDOG: &str = "systemctl start northnarrow-watchdog.service";
const GRANT: &str = "nn-admin trusted-installer-grant";

/// External audit DEP-020 (NN-AUD-440): both units stopped, the last
/// agent's pin root still protected. The window branch for this case asked
/// for an active agent and never ran: `--upgrade --grant-key` ended in
/// "PROTECTED". The installed agent is started for the window now (its unit
/// only), stopped again with the pin root removed, and not restarted.
#[test]
fn install_starts_the_agent_for_the_window_on_stale_pins() {
    for mode in ["full", "stop"] {
        let host = Host::new(&format!("install-stale-{mode}"), &[], true, true);
        let _sock = host.socket();
        let r = host.install(mode, true, Some("key-role"));
        assert_eq!(r.status, 0, "{mode}: {r:#?}");
        assert_eq!(r.called(START_AGENT), 1, "{mode}: {r:#?}");
        assert_eq!(r.called(START_WATCHDOG), 0, "{mode}: {r:#?}");
        assert!(r.index(START_AGENT) < r.index(GRANT), "{mode}: {r:#?}");
        assert!(!host.pins_left(), "{mode}: the pin root must be gone");
        assert!(
            r.stdout.contains("RESULT restart=[]"),
            "{mode}: not restarted: {r:#?}"
        );
        assert!(
            !host.dir.join("pkg-restart").exists(),
            "{mode}: the package's restart list must stay empty"
        );
        assert_eq!(
            fs::read_to_string(host.dir.join("state.northnarrow-agent")).unwrap(),
            "inactive\n",
            "{mode}: the agent ends as it was"
        );
    }
}

/// Without a key nothing is started and nothing changes; the refusal
/// names both ways out.
#[test]
fn install_on_stale_pins_without_a_key_names_the_ways_out() {
    let host = Host::new("install-stale-nokey", &[], true, true);
    let r = host.install("full", true, None);
    assert_eq!(r.status, 1, "{r:#?}");
    assert_eq!(r.called(START_AGENT), 0, "{r:#?}");
    assert!(host.pins_left());
    for hint in [
        "--grant-key",
        "reboot",
        "systemctl disable northnarrow-agent northnarrow-watchdog",
    ] {
        assert!(r.stderr.contains(hint), "{hint}: {r:#?}");
    }
}

/// A pin root nothing protects any more (or one an operator's window
/// already opened) is removed without starting anything.
#[test]
fn install_removes_unprotected_stale_pins_without_starting_the_agent() {
    let host = Host::new("install-stale-open", &[], true, false);
    let r = host.install("full", false, None);
    assert_eq!(r.status, 0, "{r:#?}");
    assert_eq!(r.called(START_AGENT), 0, "{r:#?}");
    assert!(!host.pins_left());
}

/// The started agent cannot be stopped without the window: a refused grant
/// or an agent that does not start is an explicit failure.
#[test]
fn install_on_stale_pins_reports_a_refused_grant_or_a_failed_start() {
    let host = Host::new("install-stale-norole", &[], true, true);
    let _sock = host.socket();
    let r = host.install("full", true, Some("key-norole"));
    assert_eq!(r.status, 1, "{r:#?}");
    assert!(r.stderr.contains("keeps running"), "{r:#?}");
    assert!(host.pins_left());

    let host = Host::new("install-stale-nostart", &[], true, true);
    fs::write(host.dir.join("start-fails"), "").unwrap();
    let r = host.install("full", true, Some("key-role"));
    assert_eq!(r.status, 1, "{r:#?}");
    assert!(r.stderr.contains("did not start"), "{r:#?}");
    assert!(r.stderr.contains("reboot"), "{r:#?}");
    assert!(host.pins_left());

    let host = Host::new("install-stale-nosocket", &[], true, true);
    let r = host.install("full", true, Some("key-role"));
    assert_eq!(r.status, 1, "{r:#?}");
    assert!(r.stderr.contains("did not appear"), "{r:#?}");
    assert_eq!(r.called(GRANT), 0, "{r:#?}");
}

/// A running install still takes the upgrade path: nothing extra started,
/// both units restarted at the end; without --upgrade it is refused.
#[test]
fn install_on_a_running_host_is_unchanged() {
    let both = ["northnarrow-agent", "northnarrow-watchdog"];
    let host = Host::new("install-running", &both, true, true);
    let r = host.install("full", true, Some("key-role"));
    assert_eq!(r.status, 0, "{r:#?}");
    assert_eq!(r.called(START_AGENT), 0, "{r:#?}");
    assert!(
        r.stdout
            .contains("RESULT restart=[northnarrow-watchdog northnarrow-agent]"),
        "{r:#?}"
    );
    assert!(!host.pins_left());

    let host = Host::new("install-running-noupgrade", &both, true, true);
    let r = host.install("full", false, Some("key-role"));
    assert_eq!(r.status, 1, "{r:#?}");
    assert!(r.stderr.contains("Re-run with --upgrade"), "{r:#?}");
    assert!(host.pins_left());
}

/// uninstall.sh, same case: the agent is started for the window before
/// anything is disabled; without a key it stops with nothing changed.
#[test]
fn uninstall_starts_the_agent_for_the_window_on_stale_pins() {
    let host = Host::new("uninstall-stale", &[], true, true);
    let _sock = host.socket();
    let r = host.uninstall(false, Some("key-role"));
    assert_eq!(r.status, 0, "{r:#?}");
    assert_eq!(r.called(START_AGENT), 1, "{r:#?}");
    let grant = r.index(GRANT).expect("window opened");
    assert!(r.index(START_AGENT) < Some(grant), "{r:#?}");
    let disable = r
        .index("systemctl disable northnarrow-agent.service")
        .expect("agent disabled");
    assert!(grant < disable, "{r:#?}");
    // step 2 (the pin root's removal, inside the window) is not run here
    assert_eq!(
        fs::read_to_string(host.dir.join("state.northnarrow-agent")).unwrap(),
        "inactive\n",
        "the agent started for the window is stopped again"
    );

    let host = Host::new("uninstall-stale-nokey", &[], true, true);
    let r = host.uninstall(false, None);
    assert_eq!(r.status, 1, "{r:#?}");
    assert_eq!(r.called(START_AGENT), 0, "{r:#?}");
    assert!(
        !r.calls.iter().any(|c| c.starts_with("systemctl disable")),
        "{r:#?}"
    );
    assert!(
        r.stderr.contains("--grant-key") && r.stderr.contains("reboot"),
        "{r:#?}"
    );

    // --package: the package manager removed the agent; nothing is started
    let host = Host::new("uninstall-stale-package", &[], true, true);
    let r = host.uninstall(true, None);
    assert_eq!(r.status, 0, "{r:#?}");
    assert_eq!(r.called(START_AGENT), 0, "{r:#?}");
}

/// A running, protected host without the window: the units used to be
/// disabled while their stop was refused, and the script then stopped at
/// the pin root. It stops before any disable now.
#[test]
fn uninstall_disables_nothing_when_the_stop_is_refused() {
    let both = ["northnarrow-agent", "northnarrow-watchdog"];
    let host = Host::new("uninstall-refused", &both, true, true);
    let r = host.uninstall(false, None);
    assert_eq!(r.status, 1, "{r:#?}");
    assert!(
        !r.calls.iter().any(|c| c.starts_with("systemctl disable")),
        "{r:#?}"
    );
    assert!(
        r.stderr.contains("nothing was disabled or removed"),
        "{r:#?}"
    );
    assert!(
        r.stderr.contains("northnarrow-watchdog northnarrow-agent"),
        "{r:#?}"
    );

    let host = Host::new("uninstall-window", &both, true, true);
    let r = host.uninstall(false, Some("key-role"));
    assert_eq!(r.status, 0, "{r:#?}");
    assert_eq!(r.called(START_AGENT), 0, "{r:#?}");
    for u in both {
        assert_eq!(
            r.called(&format!("systemctl disable {u}.service")),
            1,
            "{u}: {r:#?}"
        );
    }
}

// ── DEP-012: the private keys an uninstall leaves ───────────────────────

fn kept_report(case: &str, etc_key: bool, root_key: bool) -> String {
    let dir = case_dir(case);
    fs::create_dir_all(dir.join("etc")).unwrap();
    fs::create_dir_all(dir.join("state")).unwrap();
    if etc_key {
        fs::write(dir.join("etc/admin.key"), "k").unwrap();
    }
    if root_key {
        fs::write(dir.join("root-key"), "k").unwrap();
    }
    let script = format!(
        "set -euo pipefail\nETC_DIR=$1/etc; STATE_DIR=$1/state; BOOTSTRAP_KEY=$1/root-key\n{}\nkept_report\n",
        block("deploy/uninstall.sh", "kept_report")
    );
    let out = Command::new("bash")
        .arg("-c")
        .arg(script)
        .arg("bash")
        .arg(&dir)
        .output()
        .expect("bash runs");
    assert!(out.status.success(), "{out:?}");
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// External audit DEP-012 (NN-AUD-384): an install older than lab PR 96
/// left its bootstrap private key in /etc/northnarrow, which an uninstall
/// without --purge keeps; the summary named only /root/northnarrow-admin.key.
#[test]
fn uninstall_names_every_private_key_it_leaves() {
    let out = kept_report("kept-legacy", true, false);
    assert!(
        out.lines()
            .any(|l| l.contains("/etc/admin.key") && l.contains("PRIVATE key")),
        "{out}"
    );
    let out = kept_report("kept-both", true, true);
    assert_eq!(out.matches("PRIVATE key").count(), 2, "{out}");
    let out = kept_report("kept-none", false, false);
    assert!(!out.contains("PRIVATE key"), "{out}");
    assert!(out.contains("/etc ") && out.contains("/state "), "{out}");
}

/// `uninstall.sh --help` (no root needed) prints the whole usage, the key
/// option included.
#[test]
fn uninstall_help_names_the_grant_key() {
    let out = Command::new("bash")
        .arg(repo_root().join("deploy/uninstall.sh"))
        .arg("--help")
        .output()
        .expect("bash runs");
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    for want in ["--grant-key KEY", "--purge", "--package", "Same BIN_DIR"] {
        assert!(text.contains(want), "{want}: {text}");
    }
    assert!(!text.contains("set -euo pipefail"), "{text}");
}

// ── FIMR-016: control-surface files dated by their write ─────────────────

/// `install_bait SRC DST` from install.sh, with a stub `install` first on
/// PATH that drops the `-o`/`-g` owner (the test is not root): (exit
/// status, stdout).
fn install_bait(case: &Path, src: &Path, dst: &Path) -> (i32, String) {
    let bin = case.join("bin");
    fs::create_dir_all(&bin).unwrap();
    write_exec(
        &bin.join("install"),
        "args=''\nwhile [ $# -gt 0 ]; do\n  case $1 in -o|-g) shift 2 ;; *) args=\"$args '$1'\"; shift ;; esac\ndone\neval \"exec /usr/bin/install $args\"",
    );
    let script = format!(
        "set -euo pipefail\n{}\ninstall_bait \"$1\" \"$2\"\n",
        block("deploy/install.sh", "install_bait")
    );
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let out = Command::new("bash")
        .arg("-c")
        .arg(script)
        .arg("bash")
        .arg(src)
        .arg(dst)
        .env("PATH", path)
        .output()
        .expect("bash runs");
    assert!(out.stderr.is_empty() || out.status.success(), "{out:?}");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

fn mtime_secs(p: &Path) -> i64 {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(p).unwrap().mtime()
}

/// External audit FIMR-016 (NN-AUD-290): every bait said
/// `last_modified=2026-02-15T09:30:00Z` whenever it was written. The
/// install fills the template's empty `last_modified=` line with the time
/// of the write, and the file's mtime is that same second; every other
/// line is the template's. A reinstall over a file that holds its template
/// (the date aside) leaves it alone — BUG-020's skip, date and mtime kept —
/// and a file that differs is written again.
#[test]
fn install_bait_dates_the_file_by_its_write_and_skips_an_unchanged_one() {
    let case = case_dir("install-bait");
    for name in ["kill_switch.conf", "pause.flag"] {
        let src = repo_root().join("configs/honeypot-baits").join(name);
        let template = fs::read_to_string(&src).unwrap();
        assert!(template.lines().any(|l| l == "last_modified="), "{name}");
        let dst = case.join(name);
        let before = chrono::Utc::now().timestamp();
        let (rc, out) = install_bait(&case, &src, &dst);
        assert_eq!(rc, 0, "{out}");
        assert!(out.contains("writing control-surface file"), "{out}");
        let written = fs::read_to_string(&dst).unwrap();
        let stamp = written
            .lines()
            .find_map(|l| l.strip_prefix("last_modified="))
            .unwrap()
            .to_string();
        let dated = chrono::DateTime::parse_from_rfc3339(&stamp)
            .unwrap_or_else(|e| panic!("{name}: {stamp:?}: {e}"))
            .timestamp();
        assert!(stamp.ends_with('Z') && stamp.len() == 20, "{stamp}");
        assert_eq!(dated, mtime_secs(&dst), "{name}: the date is the mtime");
        assert!(dated >= before && dated <= chrono::Utc::now().timestamp());
        let undated = |t: &str| {
            t.lines()
                .filter(|l| !l.starts_with("last_modified="))
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        assert_eq!(undated(&written), undated(&template), "{name}");

        // Reinstall of the same template: skipped, date and mtime kept.
        let old = filetime_back(&dst);
        let (rc, out) = install_bait(&case, &src, &dst);
        assert_eq!(rc, 0, "{out}");
        assert!(out.contains("already matches — skip (BUG-020)"), "{out}");
        assert_eq!(fs::read_to_string(&dst).unwrap(), written);
        assert_eq!(mtime_secs(&dst), old);

        // A file in an older wording is written again.
        fs::write(&dst, template.replace("# NorthNarrow", "# Northnarrow")).unwrap();
        let (rc, out) = install_bait(&case, &src, &dst);
        assert_eq!(rc, 0, "{out}");
        assert!(out.contains("writing control-surface file"), "{out}");
        assert_eq!(
            undated(&fs::read_to_string(&dst).unwrap()),
            undated(&template)
        );
    }
}

/// Moves `p`'s mtime one hour back (`touch -d`), so that a rewrite would
/// show; returns it in seconds.
fn filetime_back(p: &Path) -> i64 {
    let back = mtime_secs(p) - 3600;
    let ok = Command::new("touch")
        .arg("-m")
        .arg("-d")
        .arg(format!("@{back}"))
        .arg(p)
        .status()
        .unwrap()
        .success();
    assert!(ok);
    back
}
