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

/// `bash <file>` for a whole install script written into the case's
/// directory: install.sh is above the kernel's limit of one argument
/// (`MAX_ARG_STRLEN`, 128 KiB), so never `bash -c <script>`.
fn script_command(case: &Path, script: &str) -> Command {
    let file = case.join("install.sh");
    fs::write(&file, script).unwrap();
    let mut cmd = Command::new("bash");
    cmd.arg(file);
    cmd
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
    is-enabled)
        u=${1%.service}; st=$(cat "$T/enabled.$u" 2>/dev/null || echo enabled)
        [ -n "$q" ] || echo "$st"
        [ "$st" = enabled ] ;;
    get-default) echo multi-user.target ;;
    list-dependencies)
        echo multi-user.target
        for u in northnarrow-agent northnarrow-watchdog; do
            st=$(cat "$T/enabled.$u" 2>/dev/null || echo enabled)
            [ "$st" = enabled ] && [ ! -e "$T/unwanted.$u" ] && echo "  $u.service"
        done
        exit 0 ;;
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
        // lot 278: `help trusted-installer-grant` names `--for-installer`
        // unless `$T/old-nn-admin` exists (an nn-admin older than the flag);
        // the grant records whether it was asked for an installer
        write_exec(
            &bin.join("nn-admin"),
            r#"echo "nn-admin $1" >> "$NN_TEST_DIR/calls"
if [ "$1" = help ] && [ "${2:-}" = trusted-installer-grant ]; then
    [ -e "$NN_TEST_DIR/old-nn-admin" ] || echo "      --for-installer   the grant is for the caller's tree"
    exit 0
fi
if [ "$1" = trusted-installer-grant ]; then
    k=; f=0; prev=
    for a in "$@"; do
        [ "$prev" = --key ] && k=$a
        if [ "$a" = --for-installer ]; then
            [ -e "$NN_TEST_DIR/old-nn-admin" ] && { echo "error: unexpected argument '--for-installer'" >&2; exit 2; }
            f=1
        fi
        prev=$a
    done
    grep -q trusted-installer "$k" || exit 1
    echo "$f" >> "$NN_TEST_DIR/for-installer"
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
        self.install_from(mode, upgrade, key, "$T/bin/northnarrow-agent")
    }

    /// [`Self::install`] with the tree's agent at `agent_bin`.
    fn install_from(&self, mode: &str, upgrade: bool, key: Option<&str>, agent_bin: &str) -> Run {
        self.install_with(mode, upgrade, key, agent_bin, "")
    }

    /// [`Self::install_from`] with `extra` (shell) set before the run.
    fn install_with(
        &self,
        mode: &str,
        upgrade: bool,
        key: Option<&str>,
        agent_bin: &str,
        extra: &str,
    ) -> Run {
        let body = section(
            "deploy/install.sh",
            "stop_nn_unit() {",
            "if [[ $MODE == stop ]]; then\n    # $PKG_RESTART_FILE hands",
        );
        let prelude = format!(
            "MODE={mode}; UPGRADE={}; GRANT_KEY={}\n\
             BIN_DIR=$T/bin; AGENT_BIN={agent_bin}\n\
             PKG_RESTART_FILE=$T/pkg-restart; BPFFS_ROOT=$T/pins\n{extra}",
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

/// Lot 273d (the lab's round 13): an upgrade of units that run but are not
/// enabled — or enabled and pulled in by no boot target — would leave a host
/// whose next boot starts no agent; it is refused before anything changes:
/// no window asked for, nothing stopped.
#[test]
fn an_upgrade_of_units_the_boot_would_not_start_is_refused() {
    let both = ["northnarrow-agent", "northnarrow-watchdog"];
    for (case, file, want) in [
        (
            "disabled",
            "enabled.northnarrow-agent",
            "northnarrow-agent.service is disabled (systemctl is-enabled)",
        ),
        (
            "unwanted",
            "unwanted.northnarrow-watchdog",
            "northnarrow-watchdog.service is enabled but not pulled in by the default target multi-user.target",
        ),
        // the review of #497 (D5, M6): enabled for this boot only
        (
            "runtime",
            "enabled.northnarrow-agent",
            "northnarrow-agent.service is enabled-runtime (systemctl is-enabled)",
        ),
    ] {
        let host = Host::new(&format!("install-boot-{case}"), &both, true, true);
        let marker = host.dir.join(file);
        fs::write(
            &marker,
            match case {
                "disabled" => "disabled\n",
                "runtime" => "enabled-runtime\n",
                _ => "",
            },
        )
        .unwrap();
        let r = host.install("full", true, Some("key-role"));
        assert_eq!(r.status, 1, "{case}: {r:#?}");
        assert!(r.stderr.contains(&format!("REFUSED — {want}")), "{case}: {r:#?}");
        assert!(r.stderr.contains("Nothing was changed."), "{case}: {r:#?}");
        assert!(
            r.stderr
                .contains("install.sh:   systemctl enable northnarrow-agent northnarrow-watchdog\n"),
            "{case}: the exact command to run: {r:#?}"
        );
        assert_eq!(r.called(GRANT), 0, "{case}: {r:#?}");
        assert!(
            !r.calls.iter().any(|c| c.starts_with("systemctl kill")),
            "{case}: {r:#?}"
        );
        assert_eq!(
            fs::read_to_string(host.dir.join("state.northnarrow-agent")).unwrap(),
            "active\n",
            "{case}: still running"
        );
    }
}

/// The re-review of #497 (RR2): the drop-ins of our units' directories
/// the tree's agent would quarantine are listed and the run refused before
/// anything is stopped — unless the operator accepts their move
/// (`--accept-dropin-quarantine`: the tree's agent moves them, then the
/// upgrade goes on); a move that fails refuses it too. The check runs once
/// the window is open (R009, lot 278), or with no agent left (an install
/// over stopped units); a tree agent without the check (an older
/// release) is a warning.
#[test]
fn the_operator_s_drop_ins_the_agent_would_quarantine_refuse_the_run_unless_accepted() {
    const CHECK: &str = "tree-agent --own-dropins check";
    const MOVE: &str = "tree-agent --own-dropins quarantine";
    let both = ["northnarrow-agent", "northnarrow-watchdog"];
    let d = "/etc/systemd/system/northnarrow-agent.service.d";
    let tree_agent = |host: &Host, check_rc: u8, move_rc: u8| {
        let tree = host.dir.join("tree");
        fs::create_dir_all(&tree).unwrap();
        write_exec(
            &tree.join("northnarrow-agent"),
            &format!(
                r#"case "$*" in
    --version) echo 'northnarrow-agent 0.0.2' ;;
    "--own-dropins check")
        echo "tree-agent $*" >> "$NN_TEST_DIR/calls"
        [ {check_rc} = 3 ] && printf '%s\n' \
            "would move {d}/10-pin.conf: found by the installer's check, sets CPUAffinity=0: fewer than the host's online ones" \
            "would move {d}/override.conf: found by the installer's check, EnvironmentFile=/etc/default/northnarrow-agent lies outside /etc/northnarrow/"
        exit {check_rc} ;;
    "--own-dropins quarantine")
        echo "tree-agent $*" >> "$NN_TEST_DIR/calls"
        echo "moved {d}/10-pin.conf -> /var/lib/northnarrow/quarantine/dropins/1-x: found by the installer's check"
        exit {move_rc} ;;
esac
exit 0"#
            ),
        );
        "$T/tree/northnarrow-agent"
    };
    let running = |r: &Run, host: &Host, case: &str| {
        assert!(
            !r.calls.iter().any(|c| c.starts_with("systemctl kill")),
            "{case}: {r:#?}"
        );
        assert_eq!(
            fs::read_to_string(host.dir.join("state.northnarrow-agent")).unwrap(),
            "active\n",
            "{case}: still running"
        );
    };
    // listed and refused, nothing stopped; the window the run opened named
    let host = Host::new("install-dropins-refused", &both, true, true);
    let bin = tree_agent(&host, 3, 0);
    let r = host.install_from("full", true, Some("key-role"), bin);
    assert_eq!(r.status, 1, "{r:#?}");
    assert!(r.index(GRANT) < r.index(CHECK), "{r:#?}");
    for want in [
        &format!("install.sh:   {d}/10-pin.conf: found by the installer's check, sets CPUAffinity=0"),
        &format!("install.sh:   {d}/override.conf: found by the installer's check, EnvironmentFile=/etc/default/northnarrow-agent lies outside"),
        "REFUSED — remove them",
        "--accept-dropin-quarantine",
        "Nothing was changed (the trusted-installer window this run opened ends at its deadline).",
    ] {
        assert!(r.stderr.contains(want), "{want}: {r:#?}");
    }
    assert_eq!(r.called(MOVE), 0, "{r:#?}");
    running(&r, &host, "refused");

    // accepted: the tree's agent moves them, the upgrade goes on
    let host = Host::new("install-dropins-accepted", &both, true, true);
    let bin = tree_agent(&host, 3, 0);
    let r = host.install_with(
        "full",
        true,
        Some("key-role"),
        bin,
        "ACCEPT_DROPIN_QUARANTINE=1",
    );
    assert_eq!(r.status, 0, "{r:#?}");
    assert!(r.index(CHECK) < r.index(MOVE), "{r:#?}");
    assert!(
        r.stdout.contains(&format!(
            "install.sh: moved {d}/10-pin.conf -> /var/lib/northnarrow/quarantine/dropins/"
        )),
        "{r:#?}"
    );

    // accepted, but a move failed: refused, nothing stopped
    let host = Host::new("install-dropins-move-failed", &both, true, true);
    let bin = tree_agent(&host, 3, 1);
    let r = host.install_with(
        "full",
        true,
        Some("key-role"),
        bin,
        "ACCEPT_DROPIN_QUARANTINE=1",
    );
    assert_eq!(r.status, 1, "{r:#?}");
    assert!(r.stderr.contains("a drop-in could not be moved"), "{r:#?}");
    running(&r, &host, "move failed");

    // none: the upgrade goes on, nothing moved
    let host = Host::new("install-dropins-none", &both, true, true);
    let bin = tree_agent(&host, 0, 0);
    let r = host.install_from("full", true, Some("key-role"), bin);
    assert_eq!(r.status, 0, "{r:#?}");
    assert_eq!((r.called(CHECK), r.called(MOVE)), (1, 0), "{r:#?}");

    // an older tree agent with no such check: a warning
    let host = Host::new("install-dropins-older", &both, true, true);
    let bin = tree_agent(&host, 2, 0);
    let r = host.install_from("full", true, Some("key-role"), bin);
    assert_eq!(r.status, 0, "{r:#?}");
    assert!(
        r.stderr
            .contains("could not judge the drop-ins of its units' directories (exit 2)"),
        "{r:#?}"
    );

    // an install over stopped units: checked with no agent to judge the
    // exec, no window to name
    let host = Host::new("install-dropins-stopped", &[], false, true);
    let bin = tree_agent(&host, 3, 0);
    let r = host.install_from("full", false, None, bin);
    assert_eq!(r.status, 1, "{r:#?}");
    assert_eq!(r.called(GRANT), 0, "{r:#?}");
    assert!(
        r.stderr.contains("install.sh: Nothing was changed.\n"),
        "{r:#?}"
    );
}

/// The coordinator's decision on #497's `NN_` drop-ins: the agent's `NN_`
/// settings in its units' drop-ins are kept configuration — listed by the
/// upgrade, never a refusal (an operator of the exec policy upgrades).
#[test]
fn an_upgrade_lists_the_agent_s_nn_settings_as_kept_configuration() {
    let both = ["northnarrow-agent", "northnarrow-watchdog"];
    let host = Host::new("install-dropins-kept", &both, true, true);
    let tree = host.dir.join("tree");
    fs::create_dir_all(&tree).unwrap();
    write_exec(
        &tree.join("northnarrow-agent"),
        r#"case "$*" in
    --version) echo 'northnarrow-agent 0.0.2' ;;
    "--own-dropins check") echo "would keep NN_EXEC_POLICY=audit set by /etc/systemd/system/northnarrow-agent.service.d/40-policy.conf"; exit 0 ;;
esac
exit 0"#,
    );
    let r = host.install_from("full", true, Some("key-role"), "$T/tree/northnarrow-agent");
    assert_eq!(r.status, 0, "{r:#?}");
    assert!(r.stdout.contains("install.sh: kept configuration in the drop-ins of the agent's own units (each setting signed by the agent):"), "{r:#?}");
    assert!(r.stdout.contains("install.sh:   NN_EXEC_POLICY=audit set by /etc/systemd/system/northnarrow-agent.service.d/40-policy.conf"), "{r:#?}");
    assert!(!r.stderr.contains("REFUSED"), "{r:#?}");
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

/// Lot 278: the upgrade opens the trusted-installer window before it
/// executes anything from its tree (the new agent's `--version`, which the
/// running agent's R009 judges): the window is granted to the script's
/// shell, and R009 records that tree at Low. A refused run (no `--upgrade`)
/// opens no window and executes nothing from the tree; an install over
/// stopped units reads the version with no agent left to judge it.
#[test]
fn install_opens_the_window_before_it_executes_its_tree() {
    const TREE: &str = "tree-agent --version";
    let both = ["northnarrow-agent", "northnarrow-watchdog"];
    let tree_agent = |host: &Host| {
        let tree = host.dir.join("tree");
        fs::create_dir_all(&tree).unwrap();
        write_exec(
            &tree.join("northnarrow-agent"),
            r#"echo "tree-agent $*" >> "$NN_TEST_DIR/calls"; echo 'northnarrow-agent 0.0.2'"#,
        );
        "$T/tree/northnarrow-agent"
    };
    let host = Host::new("install-window-first", &both, true, true);
    let bin = tree_agent(&host);
    let r = host.install_from("full", true, Some("key-role"), bin);
    assert_eq!(r.status, 0, "{r:#?}");
    assert_eq!(r.called(TREE), 1, "{r:#?}");
    assert!(r.index(GRANT) < r.index(TREE), "{r:#?}");
    assert!(
        r.stdout
            .contains("installed: northnarrow-agent 0.0.1 → new: northnarrow-agent 0.0.2"),
        "{r:#?}"
    );

    let host = Host::new("install-window-first-refused", &both, true, true);
    let bin = tree_agent(&host);
    let r = host.install_from("full", false, None, bin);
    assert_eq!(r.status, 1, "{r:#?}");
    assert_eq!((r.called(GRANT), r.called(TREE)), (0, 0), "{r:#?}");

    let host = Host::new("install-window-first-stopped", &[], false, true);
    let bin = tree_agent(&host);
    let r = host.install_from("full", false, None, bin);
    assert_eq!(r.status, 0, "{r:#?}");
    assert_eq!((r.called(GRANT), r.called(TREE)), (0, 1), "{r:#?}");
}

/// Lot 278: install.sh executes the tree's agent only in `tree_version`,
/// which runs only where its window is open or no agent judges it (the
/// harness above), and none of the tree's other binaries at all: no line
/// names `$AGENT_BIN`, `$WATCHDOG_BIN`, `$NN_ADMIN_BIN` or `$SCAN_BIN` —
/// quoted or not, braced or not (review of #493, M12b) — in a command's
/// place (the line's start, after `;`, `&&`, `||`, `|`, `$(`, `(`, `exec`,
/// …: second review, M12c/M12d), and a line naming one as an argument
/// copies it, checks it exists, compares its age or prints it.
#[test]
fn install_executes_the_tree_s_agent_only_in_tree_version() {
    let text = read("deploy/install.sh");
    let body = section("deploy/install.sh", "tree_version() {", "\n}\n");
    assert!(
        body.contains("new_ver=$(exec \"$AGENT_BIN\" --version"),
        "{body}"
    );
    // the re-review of #497 (RR2): the drop-in check, and the quarantine
    // the operator accepted, are the tree's agent's too, run the same way
    assert!(
        body.contains("DROPINS_FOUND=$(exec \"$AGENT_BIN\" --own-dropins check"),
        "{body}"
    );
    let quarantine = section("deploy/install.sh", "tree_dropins_quarantine() {", "\n}\n");
    assert!(
        quarantine.contains("DROPINS_MOVED=$(exec \"$AGENT_BIN\" --own-dropins quarantine"),
        "{quarantine}"
    );
    let start = text.find("tree_version() {").unwrap();
    let end = start + body.len();
    let q_start = text.find("tree_dropins_quarantine() {").unwrap();
    let q_end = q_start + quarantine.len();
    let mut at = 0;
    for (n, line) in text.lines().enumerate() {
        let here = at;
        at += line.len() + 1;
        let l = line.trim_start();
        if l.starts_with('#') {
            continue;
        }
        let mentions = tree_binary_mentions(l);
        if mentions.is_empty() {
            continue;
        }
        let in_tree_version = (start..end).contains(&here) || (q_start..q_end).contains(&here);
        for m in &mentions {
            if m.runs() {
                assert!(
                    in_tree_version && m.var == "AGENT_BIN",
                    "install.sh:{}: runs a binary of the tree: {line}",
                    n + 1
                );
                continue;
            }
            let names_it = l.starts_with("install ")
                || l.starts_with("require_file ")
                || l.starts_with("for staged in ")
                || l.starts_with("echo ")
                || m.after.starts_with(':')
                || m.after.starts_with(" ]]") && l.contains(" -nt ");
            assert!(
                names_it || in_tree_version,
                "install.sh:{}: may execute a binary of the tree: {line}",
                n + 1
            );
        }
    }
    // the scan sees every spelling, and every command's place
    for (line, runs) in [
        ("new_ver=$($AGENT_BIN --version)", vec![true]),
        ("x=$(\"${AGENT_BIN}\" -V)", vec![true]),
        ("$NN_ADMIN_BIN status && \"$SCAN_BIN\" -h", vec![true, true]),
        (
            "echo \"x\"; new_ver=$(\"$AGENT_BIN\" --version)",
            vec![true],
        ),
        ("install -d /tmp && \"$AGENT_BIN\" --version", vec![true]),
        ("echo \"stale: $AGENT_BIN is older\"", vec![false]),
        ("install -m 755 \"$AGENT_BIN\" \"$BIN_DIR/x\"", vec![false]),
        ("\"$SCAN_BIN:northnarrow-scan\"; do", vec![false]),
        ("$AGENT_BINARY_DIR/x", vec![]),
    ] {
        let got: Vec<bool> = tree_binary_mentions(line)
            .iter()
            .map(|m| m.runs())
            .collect();
        assert_eq!(got, runs, "{line}");
    }
}

/// A tree binary a shell line names, what precedes it and what follows it
/// (a closing quote skipped).
struct Mention<'a> {
    var: &'static str,
    before: &'a str,
    after: &'a str,
}

impl Mention<'_> {
    /// In a command's place: the line's start, or after a separator or a
    /// word that starts a command — not a `VAR:name` word of a list.
    fn runs(&self) -> bool {
        if self.after.starts_with(':') {
            return false;
        }
        let b = self.before.trim_end().trim_end_matches('"').trim_end();
        b.is_empty()
            || ["$(", "(", ";", "&&", "||", "|", "`", "!", "{"]
                .iter()
                .any(|s| b.ends_with(s))
            || [
                "exec", "then", "do", "else", "eval", "command", "env", "nohup", "sudo",
            ]
            .iter()
            .any(|w| b == *w || b.ends_with(&format!(" {w}")) || b.ends_with(&format!("({w}")))
    }
}

/// The tree binaries a shell line names — `$VAR` (not a longer name) or
/// `${VAR}` — in the order they appear.
fn tree_binary_mentions(line: &str) -> Vec<Mention<'_>> {
    let mut out = Vec::new();
    for var in ["AGENT_BIN", "WATCHDOG_BIN", "NN_ADMIN_BIN", "SCAN_BIN"] {
        for form in [format!("${{{var}}}"), format!("${var}")] {
            let mut from = 0;
            while let Some(i) = line[from..].find(&form) {
                let at = from + i;
                let after = &line[at + form.len()..];
                from = at + form.len();
                if !form.ends_with('}')
                    && after
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    continue;
                }
                out.push((
                    at,
                    Mention {
                        var,
                        before: &line[..at],
                        after: after.strip_prefix('"').unwrap_or(after),
                    },
                ));
            }
        }
    }
    out.sort_by_key(|(at, _)| *at);
    out.into_iter().map(|(_, m)| m).collect()
}

/// Lot 278 (reviews of #493, note a): the scripts ask for their windows
/// for their own tree — every grant they run passes `--for-installer` when
/// the installed nn-admin knows it, and the plain grant when it does not
/// (the first upgrade to it) — and a grant by hand names no installer.
#[test]
fn the_scripts_ask_for_their_windows_as_installers() {
    for script in ["deploy/install.sh", "deploy/uninstall.sh"] {
        let text = read(script);
        let grants: Vec<&str> = text
            .lines()
            .filter(|l| !l.trim_start().starts_with('#') && !l.trim_start().starts_with("echo "))
            .filter(|l| l.contains("nn-admin\" trusted-installer-grant"))
            .collect();
        assert!(!grants.is_empty(), "{script}: no grant");
        for l in grants {
            assert!(
                l.contains(
                    "\"$BIN_DIR/nn-admin\" trusted-installer-grant ${for_installer[@]+\"${for_installer[@]}\"}"
                ),
                "{script}: a grant not for the script's tree: {l}"
            );
        }
        assert!(
            text.contains(
                "$(\"$BIN_DIR/nn-admin\" help trusted-installer-grant 2>/dev/null || true)"
            ),
            "{script}: asks the installed nn-admin whether it knows the flag"
        );
    }
    // the upgrade's window, asked as the installer — and with an nn-admin
    // older than the flag, the plain grant (the window still opens)
    for (old, want) in [(false, "1"), (true, "0")] {
        let both = ["northnarrow-agent", "northnarrow-watchdog"];
        let host = Host::new(&format!("install-for-installer-{old}"), &both, true, true);
        if old {
            fs::write(host.dir.join("old-nn-admin"), "").unwrap();
        }
        let r = host.install("full", true, Some("key-role"));
        assert_eq!(r.status, 0, "{r:#?}");
        let asked = fs::read_to_string(host.dir.join("for-installer")).unwrap();
        assert!(
            asked.lines().all(|l| l == want) && !asked.is_empty(),
            "{asked:?}"
        );
        let host = Host::new(&format!("uninstall-for-installer-{old}"), &both, true, true);
        if old {
            fs::write(host.dir.join("old-nn-admin"), "").unwrap();
        }
        let r = host.uninstall(false, Some("key-role"));
        assert_eq!(r.status, 0, "{r:#?}");
        let asked = fs::read_to_string(host.dir.join("for-installer")).unwrap();
        assert!(
            asked.lines().all(|l| l == want) && !asked.is_empty(),
            "{asked:?}"
        );
    }
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

// ── Lab PR 216 (capability C23): /run/northnarrow and the failure handler ──

/// Static review C-43 / G-06: install.sh created `/run/northnarrow` 0755
/// while the units declare `RuntimeDirectoryMode=0700`; the agent's next
/// start corrected it, every run of install.sh opened it again. The section
/// runs against a stub `install` that records its arguments.
#[test]
fn install_creates_the_run_directory_0700() {
    let dir = case_dir("run-dir-mode");
    let bin = dir.join("bin");
    fs::create_dir_all(&bin).unwrap();
    write_exec(&bin.join("install"), r#"echo "$*" >> "$NN_TEST_LOG""#);
    let log = dir.join("install.log");
    // Lab PR 220: `RUN_DIR` is set (overridable) at the top of install.sh;
    // the section starts at the directory's creation.
    let body = section(
        "deploy/install.sh",
        "# Lab PR 216 (static review C-43 / G-06): 0700",
        "declare -A HONEYPOT_BAIT_DIRS",
    );
    let out = Command::new("bash")
        .arg("-c")
        .arg(&body)
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("RUN_DIR", "/run/northnarrow")
        .env("NN_TEST_LOG", &log)
        .output()
        .expect("bash runs");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let calls = fs::read_to_string(&log).unwrap();
    assert_eq!(calls.trim(), "-d -m 0700 -o root -g root /run/northnarrow");
    assert!(String::from_utf8_lossy(&out.stdout).contains("mode 0700"));
}

/// The watchdog unit's `OnFailure=` handler ships wherever the units do:
/// install.sh requires and installs it (rewritten for `BIN_DIR` like the
/// others) and removes the install.sh copy when a package takes over,
/// uninstall.sh removes it, the packages carry it, and the tarball's
/// `deploy/systemd` copy includes it.
#[test]
fn the_watchdog_failure_handler_ships_with_the_units() {
    const UNIT: &str = "northnarrow-watchdog-failed.service";
    assert!(repo_root().join("deploy/systemd").join(UNIT).is_file());
    let install = read("deploy/install.sh");
    assert!(install.contains(&format!(
        "WATCHDOG_FAILED_UNIT_SRC=\"$REPO_ROOT/deploy/systemd/{UNIT}\""
    )));
    assert!(install.contains("require_file \"$WATCHDOG_FAILED_UNIT_SRC\""));
    // Lab PR 220: staged beside the installed unit, then renamed over it
    // with the others (and backed up for a rollback).
    assert!(install.contains(&format!(
        "install_unit \"$WATCHDOG_FAILED_UNIT_SRC\" \"$UNIT_DIR/{UNIT}.nn-new\""
    )));
    assert!(install.contains(
        "\"$UNIT_DIR/northnarrow-watchdog-failed.service\" \"$UNIT_DIR/northnarrow.slice\"; do"
    ));
    assert!(install.contains(
        "for f in northnarrow-agent northnarrow-watchdog northnarrow-watchdog-failed; do echo \"$UNIT_DIR/$f.service\"; done"
    ));
    assert!(
        install.contains(&format!("/etc/systemd/system/{UNIT}")),
        "package migration"
    );
    let uninstall = read("deploy/uninstall.sh");
    assert!(
        uninstall.contains(
            "for u in northnarrow-agent northnarrow-watchdog northnarrow-watchdog-failed; do"
        ),
        "uninstall.sh removes the handler unit"
    );
    let packages = read("deploy/release/mk-packages.sh");
    assert!(packages.contains(
        "for u in northnarrow-agent northnarrow-watchdog northnarrow-watchdog-failed; do"
    ));
    assert!(
        packages.contains(&format!("/usr/lib/systemd/system/{UNIT}\n")),
        "rpm %files"
    );
    assert!(read("deploy/release/mk-tarball.sh").contains("deploy/systemd"));
}

/// Lot 273d (the review of #492): the units' slice of their own ships,
/// switches and leaves with them — `system.slice.d` no longer reaches the
/// agent and the watchdog — and both units name it.
#[test]
fn the_units_slice_ships_with_the_units() {
    const SLICE: &str = "northnarrow.slice";
    let unit = read(&format!("deploy/systemd/{SLICE}"));
    for want in ["[Slice]", "RefuseManualStop=yes", "IgnoreOnIsolate=yes"] {
        assert!(unit.contains(want), "{want}");
    }
    for u in ["northnarrow-agent.service", "northnarrow-watchdog.service"] {
        assert!(
            read(&format!("deploy/systemd/{u}")).contains("\nSlice=northnarrow.slice\n"),
            "{u}"
        );
    }
    let install = read("deploy/install.sh");
    for want in [
        "SLICE_UNIT_SRC=\"$REPO_ROOT/deploy/systemd/northnarrow.slice\"",
        "require_file \"$SLICE_UNIT_SRC\"",
        "install_unit \"$SLICE_UNIT_SRC\" \"$UNIT_DIR/northnarrow.slice.nn-new\"",
        "\"$UNIT_DIR/northnarrow.slice\"; do",
        "    echo \"$UNIT_DIR/northnarrow.slice\"",
        "/etc/systemd/system/northnarrow.slice; do",
    ] {
        assert!(install.contains(want), "{want}");
    }
    let uninstall = read("deploy/uninstall.sh");
    assert!(uninstall.contains("rm -f \"$UNIT_DIR/northnarrow.slice\""));
    assert!(uninstall.contains("\"$DROPIN_ROOT/northnarrow.slice.d\""));
    let packages = read("deploy/release/mk-packages.sh");
    assert!(packages.contains(
        "install -m 0644 deploy/systemd/northnarrow.slice \"$root/usr/lib/systemd/system/northnarrow.slice\""
    ));
    assert!(
        packages.contains("/usr/lib/systemd/system/northnarrow.slice\n"),
        "rpm %files"
    );
    assert!(
        read(".github/workflows/release.yml").contains("usr/lib/systemd/system/northnarrow.slice")
    );
    // the slice's drop-in directories, made empty for the agent to register
    // NOCREATE
    assert!(read("deploy/systemd/northnarrow-agent.service").contains(
        "/etc/systemd/system/northnarrow.slice.d /run/systemd/system/northnarrow.slice.d"
    ));
}

// ── Lab PR 220: the transactional upgrade and the blocking provenance ────
//
// install.sh as a whole, run as the test user: the one `require_root` call
// left out, every host path pointed into the case directory, and stubs
// first on PATH for what touches the host. The stubs keep the anti-tamper's
// rules: while a pin root exists and no trusted-installer window is open,
// a write, rename or removal under the agent's binaries, units, `/etc`,
// state, drop-ins or pins is refused, and so is PID 1's signal to the
// units; an agent start rolls a new session (the window closes). A start
// runs the binary the installed unit names (`ExecStart=`), so what boots is
// what the files say: a fake agent that pins, writes its pid file, its own
// program ids and its health event (or the failure its tree asks for), a
// fake watchdog that logs its PROTECTED_PIDS registration. Every write of a
// stub outside the case directory or /tmp is refused (the configure mode
// names real system paths).

const SANDBOX_LIB: &str = r#"T=$NN_TEST_DIR
inside() { case "$1" in "$NN_TEST_SANDBOX"/*|/tmp/*) return 0 ;; esac; return 1; }
protected() {
    [ -d "$T/pins" ] && [ ! -e "$T/window" ] || return 1
    case "$1" in "$T"/bin/*|"$T"/units/*|"$T"/etc/*|"$T"/state/*|"$T"/dropins/*|"$T"/pins|"$T"/pins/*) return 0 ;; esac
    return 1
}
refuse() { echo "$1: cannot write '$2': Operation not permitted" >&2; exit 1; }
"#;

/// One install.sh host with two trees: `old` (installed first) and `new`.
struct Lab {
    case: PathBuf,
    root: PathBuf,
}

/// How a tree's fake agent or watchdog behaves at its start.
#[derive(Clone, Copy)]
struct Build {
    version: &'static str,
    agent_fail: &'static str,
    watchdog_fail: &'static str,
    reads_marker: bool,
}

const OLD: Build = Build {
    version: "0.0.1",
    agent_fail: "none",
    watchdog_fail: "none",
    reads_marker: true,
};
const NEW: Build = Build {
    version: "0.0.2",
    agent_fail: "none",
    watchdog_fail: "none",
    reads_marker: true,
};

fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for e in fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        let to = dst.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &to);
        } else {
            fs::copy(e.path(), &to).unwrap();
        }
    }
}

fn append(path: &Path, line: &str) {
    let mut text = fs::read_to_string(path).unwrap();
    text.push_str(line);
    fs::write(path, text).unwrap();
}

/// mtime `secs` seconds ago.
fn age(p: &Path, secs: i64) {
    let at = chrono::Utc::now().timestamp() - secs;
    let ok = Command::new("touch")
        .arg("-m")
        .arg("-d")
        .arg(format!("@{at}"))
        .arg(p)
        .status()
        .unwrap()
        .success();
    assert!(ok);
}

impl Lab {
    fn new(case: &str) -> Lab {
        let case = case_dir(&format!("lab-{case}"));
        let root = case.join("root");
        let stub = case.join("stub");
        for d in [
            "bin",
            "units",
            "dropins",
            "etc",
            "etc-systemd",
            "state",
            "run",
            "journal",
            "txn",
            "nonft",
        ] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        fs::create_dir_all(case.join("tmp")).unwrap();
        fs::create_dir_all(&stub).unwrap();
        for u in ["northnarrow-agent", "northnarrow-watchdog"] {
            fs::create_dir_all(root.join("cg").join(u)).unwrap();
            fs::write(root.join("cg").join(u).join("cgroup.procs"), "").unwrap();
            fs::write(root.join(format!("state.{u}")), "inactive\n").unwrap();
        }
        fs::write(root.join("key-role"), "trusted-installer\n").unwrap();
        let lib = SANDBOX_LIB;
        write_exec(
            &stub.join("systemctl"),
            &format!(
                r#"{lib}
echo "systemctl $*" >> "$T/calls"
cmd=$1; shift
q=; if [ "${{1:-}}" = --quiet ]; then q=1; shift; fi
case "$cmd" in
    is-active)
        u=${{1%.service}}; st=$(cat "$T/state.$u" 2>/dev/null || echo inactive)
        [ -n "$q" ] || echo "$st"
        [ "$st" = active ] ;;
    is-enabled)
        # the marker's content is the state (the review of #497, D5:
        # `enable --runtime` is "enabled-runtime", exit 0 as systemd's)
        if [ -e "$T/enabled.${{1%.service}}" ]; then
            st=$(cat "$T/enabled.${{1%.service}}"); [ -n "$st" ] || st=enabled
            [ -n "$q" ] || echo "$st"
        else [ -n "$q" ] || echo disabled; exit 1; fi ;;
    get-default) echo multi-user.target ;;
    list-dependencies)
        echo multi-user.target
        for u in northnarrow-agent northnarrow-watchdog; do
            [ -e "$T/enabled.$u" ] && [ ! -e "$T/unwanted.$u" ] && echo "  $u.service"
        done
        exit 0 ;;
    enable)
        st=enabled
        for a; do [ "$a" = --runtime ] && st=enabled-runtime; done
        for a; do case "$a" in --*) ;; *) echo "$st" > "$T/enabled.${{a%.service}}" ;; esac; done ;;
    disable) for a; do /bin/rm -f "$T/enabled.${{a%.service}}"; done ;;
    start)
        u=${{1%.service}}
        [ "$(cat "$T/state.$u" 2>/dev/null)" = active ] && exit 0
        exe=$(sed -n 's/^ExecStart=\([^ ]*\).*/\1/p' "$T/units/$u.service" 2>/dev/null)
        pid=$(( $(cat "$T/nextpid" 2>/dev/null || echo 1000) + 1 )); echo "$pid" > "$T/nextpid"
        if [ -n "$exe" ] && "$exe" __nn_test_boot "$pid"; then
            echo active > "$T/state.$u"; echo "$pid" > "$T/cg/$u/cgroup.procs"; echo "$pid" > "$T/mainpid.$u"
            echo "started $u $("$exe" --version)" >> "$T/calls"
        else
            echo failed > "$T/state.$u"; : > "$T/cg/$u/cgroup.procs"; echo 0 > "$T/mainpid.$u"
            echo "start failed $u" >> "$T/calls"
            exit 1
        fi ;;
    kill)
        u=${{2%.service}}
        # PID 1 relays root's signal only inside the window (EBPF-001)
        if [ -d "$T/pins" ] && [ ! -e "$T/window" ]; then exit 1; fi
        echo inactive > "$T/state.$u"; : > "$T/cg/$u/cgroup.procs"; echo 0 > "$T/mainpid.$u"
        if [ "$u" = northnarrow-agent ]; then /bin/rm -f "$T/sock-up"; fi ;;
    show)
        u=${{4%.service}}
        case "$2" in
            ControlGroup) echo "/../../..$T/cg/$u" ;;
            MainPID) cat "$T/mainpid.$u" 2>/dev/null || echo 0 ;;
        esac ;;
    daemon-reload)
        if [ -e "$T/fail-daemon-reload" ]; then /bin/rm -f "$T/fail-daemon-reload"; exit 1; fi
        # lot 273d: a switch that loses the watchdog's enablement link
        if [ -e "$T/lose-enable" ]; then /bin/rm -f "$T/lose-enable" "$T/enabled.northnarrow-watchdog"; fi ;;
    *) exit 0 ;;
esac"#
            ),
        );
        write_exec(
            &stub.join("journalctl"),
            r#"u=; p=
for a; do
    case "$a" in
        _SYSTEMD_UNIT=*) u=${a#_SYSTEMD_UNIT=}; u=${u%.service} ;;
        _PID=*) p=${a#_PID=} ;;
    esac
done
cat "$NN_TEST_DIR/journal/$u.$p" 2>/dev/null
exit 0"#,
        );
        write_exec(
            &stub.join("bpftool"),
            r#"if [ "$2" = show ] && [ "${3:-}" = id ]; then
    if [ -e "$NN_TEST_DIR/progs-stuck" ]; then echo "$4: lsm  name x"; exit 0; fi
    echo "Error: get by id ($4): No such file or directory" >&2; exit 255
fi
exit 0"#,
        );
        write_exec(&stub.join("sleep"), "exit 0");
        write_exec(&stub.join("chown"), "exit 0");
        write_exec(&stub.join("chattr"), "exit 0");
        // Lab PR 223: the scanner's system account — never the host's
        // (review of #480, F11: the entries a real getent gives, the
        // account install.sh creates; `id`, login.defs and /proc the
        // case's own).
        write_exec(
            &stub.join("getent"),
            r#"[ -e "$NN_TEST_DIR/scan-user" ] || exit 2
case $1:${2:-} in
  passwd:northnarrow-scan|passwd:) echo "northnarrow-scan:x:990:990::/nonexistent:/usr/sbin/nologin" ;;
  shadow:northnarrow-scan) echo "northnarrow-scan:!:19000::::::" ;;
  *) exit 2 ;;
esac"#,
        );
        write_exec(
            &stub.join("id"),
            r#"[ "$1" = -G ] && [ "$2" = northnarrow-scan ] && [ -e "$NN_TEST_DIR/scan-user" ] && echo 990"#,
        );
        fs::write(case.join("login.defs"), "UID_MIN 1000\nGID_MIN 1000\n").unwrap();
        fs::create_dir_all(case.join("proc")).unwrap();
        write_exec(
            &stub.join("useradd"),
            r#"echo "useradd $*" >> "$NN_TEST_DIR/calls"; : > "$NN_TEST_DIR/scan-user""#,
        );
        write_exec(
            &stub.join("logger"),
            r#"echo "$*" >> "$NN_TEST_DIR/logged""#,
        );
        // no attestation verifier unless a case installs one
        write_exec(&stub.join("gh"), "exit 1");
        write_exec(&stub.join("cosign"), "exit 1");
        write_exec(
            &stub.join("install"),
            &format!(
                r#"{lib}
args=''; dir=0; last=''
while [ $# -gt 0 ]; do
    case $1 in
        -o|-g) shift 2 ;;
        -d) dir=1; args="$args '$1'"; shift ;;
        *) args="$args '$1'"; last=$1; shift ;;
    esac
done
if [ "$dir" = 0 ]; then
    inside "$last" || refuse install "$last"
    protected "$last" && refuse install "$last"
    if [ -e "$T/fail-install" ] && case "$last" in *"$(cat "$T/fail-install")") true ;; *) false ;; esac; then
        /bin/rm -f "$T/fail-install"; refuse install "$last"
    fi
fi
eval "exec /usr/bin/install $args""#
            ),
        );
        write_exec(
            &stub.join("mv"),
            &format!(
                r#"{lib}
for a; do last=$a; done
for a; do
    case "$a" in -*) continue ;; esac
    inside "$a" || refuse mv "$a"
    protected "$a" && refuse mv "$a"
done
if [ -e "$T/fail-mv" ] && case "$last" in *"$(cat "$T/fail-mv")") true ;; *) false ;; esac; then
    /bin/rm -f "$T/fail-mv"; refuse mv "$last"
fi
exec /bin/mv "$@""#
            ),
        );
        write_exec(
            &stub.join("cp"),
            &format!(
                r#"{lib}
for a; do last=$a; done
inside "$last" || refuse cp "$last"
protected "$last" && refuse cp "$last"
exec /bin/cp "$@""#
            ),
        );
        write_exec(
            &stub.join("rm"),
            &format!(
                r#"{lib}
for a; do
    case "$a" in -*) continue ;; esac
    inside "$a" || refuse rm "$a"
    protected "$a" && refuse rm "$a"
done
exec /bin/rm "$@""#
            ),
        );
        let lab = Lab { case, root };
        lab.tree("old", OLD, false);
        lab.tree("new", NEW, true);
        lab
    }

    /// A source tree: the repository's units and configs (`tweak`: a new
    /// release's — a unit, the journald config, a shipped list and a bait
    /// changed), fake binaries, an eBPF object older than the agent.
    fn tree(&self, name: &str, b: Build, tweak: bool) -> PathBuf {
        let tree = self.case.join(name);
        let _ = fs::remove_dir_all(&tree);
        fs::create_dir_all(tree.join("deploy")).unwrap();
        copy_dir(
            &repo_root().join("deploy/systemd"),
            &tree.join("deploy/systemd"),
        );
        copy_dir(&repo_root().join("configs"), &tree.join("configs"));
        if tweak {
            append(
                &tree.join("deploy/systemd/northnarrow-agent.service"),
                "# lab PR 220 test: a newer release\n",
            );
            append(
                &tree.join("deploy/systemd/journald@northnarrow.conf"),
                "# lab PR 220 test: a newer release\n",
            );
            append(&tree.join("configs/fim-paths.v1"), "/etc/nn-test-newer\n");
            append(
                &tree.join("configs/honeypot-baits/kill_switch.conf"),
                "# newer wording\n",
            );
        }
        let ebpf = tree.join("agent-ebpf/target/bpfel-unknown-none/release");
        fs::create_dir_all(&ebpf).unwrap();
        fs::write(ebpf.join("northnarrow-agent-ebpf"), format!("ebpf {name}")).unwrap();
        fs::write(ebpf.join("northnarrow-agent-ebpf.buildhash"), "stamp").unwrap();
        age(&ebpf.join("northnarrow-agent-ebpf"), 3600);
        age(&ebpf.join("northnarrow-agent-ebpf.buildhash"), 3600);
        self.binaries(name, b);
        tree
    }

    fn binaries(&self, tree: &str, b: Build) {
        let rel = self.case.join(tree).join("target/release");
        fs::create_dir_all(&rel).unwrap();
        let (v, af, wf) = (b.version, b.agent_fail, b.watchdog_fail);
        let marker = u8::from(b.reads_marker);
        write_exec(
            &rel.join("northnarrow-agent"),
            &format!(
                r#"# fake northnarrow-agent {v}
FAIL={af}; READS_MARKER={marker}
case "${{1:-}}" in
    --version) echo "northnarrow-agent {v}"; exit 0 ;;
    --own-dropins) echo "own-dropins ${{2:-}}" >> "$NN_TEST_DIR/own-dropins.calls"
        [ -s "$NN_TEST_DIR/own-dropins" ] && {{ cat "$NN_TEST_DIR/own-dropins"; exit 3; }}; exit 0 ;;
    __nn_test_boot) ;;
    *) exit 0 ;;
esac
T=$NN_TEST_DIR; pid=$2; j="$T/journal/northnarrow-agent.$pid"; ts=2026-10-20T10:00:00.123456Z
[ "$FAIL" = start ] && exit 1
mkdir -p "$T/pins/maps"; : > "$T/pins/maps/PROTECTED_PIDS"
/bin/rm -f "$T/window"
[ "$FAIL" = start-pinned ] && exit 1
echo "$pid" > "$T/run/agent.pid"
echo 17 > "$T/run/bpf-own-ids"
[ -s "$T/etc/agent_id" ] || echo 00112233445566778899aabbccddeeff > "$T/etc/agent_id"
echo '{{"op":"agent_boot","extra":{{"version":"{v}"}}}}' >> "$T/etc/audit.log"
if [ "$READS_MARKER" = 1 ] && [ -e "$T/run/upgrade-rolled-back.json" ]; then
    echo "{{\"op\":\"upgrade_rolled_back\",\"extra\":$(cat "$T/run/upgrade-rolled-back.json")}}" >> "$T/etc/audit.log"
    /bin/rm -f "$T/run/upgrade-rolled-back.json"
fi
if [ "$FAIL" = tamper-backup ]; then
    for f in "$T"/txn/*/backup"$T"/bin/northnarrow-agent; do [ -e "$f" ] && echo tampered >> "$f"; done
fi
case "$FAIL" in
    health|tamper-backup) echo "$ts  INFO NorthNarrow agent starting..." >> "$j" ;;
    forged) echo "$ts  INFO VERDICT rule=R001 file=\"x anti-tamper: all LSM hooks attached deny_attached=18 deny_expected=18\"" >> "$j"
            echo "x anti-tamper: all LSM hooks attached deny_attached=18 deny_expected=18" >> "$j" ;;
    degraded) echo "$ts ERROR anti-tamper: DENY HOOK SHORTFALL — a protection is silently absent deny_attached=17 deny_expected=18 missing=[\"inode_rename\"] infra_failed=[] allow_degraded=true" >> "$j" ;;
    observe) echo "$ts  WARN anti-tamper: OBSERVE HOOK SHORTFALL — module-load telemetry absent (R018 blind) deny_attached=18 deny_expected=18 observe_failed=[\"kernel_module_request\"]" >> "$j" ;;
    *) echo "$ts  INFO anti-tamper: all LSM hooks attached deny_attached=18 deny_expected=18" >> "$j" ;;
esac
[ "$FAIL" = socket ] || : > "$T/sock-up"
exit 0"#
            ),
        );
        write_exec(
            &rel.join("northnarrow-watchdog"),
            &format!(
                r#"# fake northnarrow-watchdog {v}
FAIL={wf}
case "${{1:-}}" in
    --version) echo "northnarrow-watchdog {v}"; exit 0 ;;
    __nn_test_boot) ;;
    *) exit 0 ;;
esac
T=$NN_TEST_DIR; pid=$2
[ "$FAIL" = start ] && exit 1
[ "$FAIL" = noregister ] || echo "2026-10-20T10:00:01.000000Z  INFO watchdog: watchdog PID registered in PROTECTED_PIDS pid=$pid bpffs_root=$T/pins" >> "$T/journal/northnarrow-watchdog.$pid"
exit 0"#
            ),
        );
        // Lab PR 223: the exec quarantine's scanner, installed with the
        // binaries (the agent spawns it only with --exec-quarantine).
        write_exec(
            &rel.join("northnarrow-scan"),
            &format!(
                r#"# fake northnarrow-scan {v}
case "${{1:-}}" in
    --version) echo "northnarrow-scan {v}" ;;
esac
exit 0"#
            ),
        );
        write_exec(
            &rel.join("nn-admin"),
            &format!(
                r#"# fake nn-admin {v}
T=$NN_TEST_DIR
echo "nn-admin $1" >> "$T/calls"
case "${{1:-}}" in
    trusted-installer-grant) grep -q trusted-installer "$3" || exit 1; [ -e "$T/sock-up" ] || exit 1; : > "$T/window" ;;
    status) [ -e "$T/sock-up" ] || exit 1; echo '{{"posture":"Normal"}}' ;;
    init) echo private > "$3"; echo "ed25519 AAAA" >> "$5" ;;
esac
exit 0"#
            ),
        );
    }

    fn env(&self, cmd: &mut Command) {
        let r = &self.root;
        let path = format!(
            "{}:{}",
            self.case.join("stub").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        cmd.env("PATH", path)
            .env("NN_TEST_DIR", r)
            .env("NN_TEST_SANDBOX", &self.case)
            .env("TMPDIR", self.case.join("tmp"))
            .env("BIN_DIR", r.join("bin"))
            .env("UNIT_DIR", r.join("units"))
            .env("DROPIN_ROOT", r.join("dropins"))
            .env("ETC_DIR", r.join("etc"))
            .env("STATE_DIR", r.join("state"))
            .env("RUN_DIR", r.join("run"))
            .env("BPFFS_ROOT", r.join("pins"))
            .env(
                "JOURNALD_NS_CONF",
                r.join("etc-systemd/journald@northnarrow.conf"),
            )
            .env("UPGRADE_TXN_ROOT", r.join("txn"))
            .env("OWN_IDS_FILE", r.join("run/bpf-own-ids"))
            .env("ADMIN_SOCKET", r.join("run/admin.sock"))
            .env("PKG_RESTART_FILE", r.join("pkg-restart"))
            .env("NFT_DIRS", r.join("nonft"))
            .env("LOGIN_DEFS", self.case.join("login.defs"))
            .env("PROC_ROOT", self.case.join("proc"))
            .env("HEALTH_TIMEOUT", "2")
            .env("LSM_DRAIN_TIMEOUT", "2")
            .env("ADMIN_SOCKET_WAIT", "1");
    }

    /// install.sh from tree `tree` (the `require_root` call left out).
    fn install(&self, tree: &str, args: &[&str]) -> Run {
        let text = read("deploy/install.sh");
        assert_eq!(text.matches("\nrequire_root\n").count(), 1);
        let script = text.replace("\nrequire_root\n", "\n");
        let t = self.case.join(tree);
        let mut cmd = script_command(&self.case, &script);
        cmd.args(args)
            .args([
                "--without-nftables",
                "--admin-key-out",
                self.root.join("admin.key").to_str().unwrap(),
            ])
            .env("REPO_ROOT", &t)
            .env("TARGET_DIR", t.join("target/release"));
        self.env(&mut cmd);
        self.finish(cmd)
    }

    fn finish(&self, mut cmd: Command) -> Run {
        let _ = fs::remove_file(self.root.join("calls"));
        let out = cmd.output().expect("bash runs");
        Run {
            status: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
            calls: fs::read_to_string(self.root.join("calls"))
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .collect(),
        }
    }

    fn systemctl(&self, args: &[&str]) -> bool {
        let mut cmd = Command::new(self.case.join("stub/systemctl"));
        cmd.args(args);
        self.env(&mut cmd);
        cmd.status().unwrap().success()
    }

    /// The old release installed fresh, enabled and running.
    fn install_old(&self) {
        let r = self.install("old", &["--source-tree"]);
        assert_eq!(r.status, 0, "fresh install: {r:#?}");
        assert!(self.systemctl(&[
            "enable",
            "northnarrow-agent.service",
            "northnarrow-watchdog.service"
        ]));
        assert!(self.systemctl(&["start", "northnarrow-agent.service"]));
        assert!(self.systemctl(&["start", "northnarrow-watchdog.service"]));
        assert!(
            self.root.join("pins").is_dir(),
            "the old agent pinned its hooks"
        );
    }

    fn key(&self) -> String {
        self.root.join("key-role").display().to_string()
    }

    fn upgrade(&self) -> Run {
        let key = self.key();
        self.install("new", &["--source-tree", "--upgrade", "--grant-key", &key])
    }

    fn state(&self, unit: &str) -> String {
        fs::read_to_string(self.root.join(format!("state.{unit}")))
            .unwrap()
            .trim()
            .to_string()
    }

    fn logged(&self) -> String {
        fs::read_to_string(self.root.join("logged")).unwrap_or_default()
    }

    fn audit_rows(&self, op: &str) -> Vec<serde_json::Value> {
        fs::read_to_string(self.root.join("etc/audit.log"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v["op"] == op)
            .collect()
    }

    fn txn_entries(&self) -> Vec<PathBuf> {
        fs::read_dir(self.root.join("txn"))
            .map(|d| d.map(|e| e.unwrap().path()).collect())
            .unwrap_or_default()
    }

    /// Every file an install writes or the agent's hooks protect, with its
    /// bytes, mode and mtime — what the new agent appends (the audit
    /// chain) and writes at boot (its pid file, its program ids) left out.
    fn snapshot(&self) -> std::collections::BTreeMap<String, (Vec<u8>, u32, i64)> {
        use std::os::unix::fs::MetadataExt;
        fn walk(
            base: &Path,
            dir: &Path,
            out: &mut std::collections::BTreeMap<String, (Vec<u8>, u32, i64)>,
        ) {
            let Ok(rd) = fs::read_dir(dir) else { return };
            for e in rd {
                let e = e.unwrap();
                let p = e.path();
                let rel = p.strip_prefix(base).unwrap().display().to_string();
                if e.file_type().unwrap().is_dir() {
                    out.insert(format!("{rel}/"), (Vec::new(), 0, 0));
                    walk(base, &p, out);
                } else if !["etc/audit.log", "run/agent.pid", "run/bpf-own-ids"]
                    .contains(&rel.as_str())
                {
                    let m = fs::symlink_metadata(&p).unwrap();
                    out.insert(rel, (fs::read(&p).unwrap(), m.mode(), m.mtime()));
                }
            }
        }
        let mut out = std::collections::BTreeMap::new();
        for d in [
            "bin",
            "units",
            "dropins",
            "etc",
            "state",
            "run",
            "etc-systemd",
        ] {
            walk(&self.root, &self.root.join(d), &mut out);
        }
        out
    }
}

/// The paths whose bytes, mode or mtime differ, and the ones only one side has.
fn snapshot_diff(
    a: &std::collections::BTreeMap<String, (Vec<u8>, u32, i64)>,
    b: &std::collections::BTreeMap<String, (Vec<u8>, u32, i64)>,
) -> Vec<String> {
    let mut out = Vec::new();
    for (k, v) in a {
        match b.get(k) {
            None => out.push(format!("gone: {k}")),
            Some(w) if w.0 != v.0 => out.push(format!("bytes differ: {k}")),
            Some(w) if w.1 != v.1 => out.push(format!("mode {:o} -> {:o}: {k}", v.1, w.1)),
            Some(w) if w.2 != v.2 => out.push(format!("mtime differs: {k}")),
            Some(_) => {}
        }
    }
    for k in b.keys() {
        if !a.contains_key(k) {
            out.push(format!("new: {k}"));
        }
    }
    out
}

/// The versions the stub started, in order (`started <unit> <version line>`).
fn started(r: &Run, unit: &str) -> Vec<String> {
    let prefix = format!("started {unit} ");
    r.calls
        .iter()
        .filter_map(|c| c.strip_prefix(&prefix).map(str::to_string))
        .collect()
}

/// Lot 273d: running is not enough — an upgrade whose switch lost a unit's
/// enablement fails its health check (the next boot would start no agent)
/// and is rolled back: the old release back, both units enabled again.
#[test]
fn an_upgrade_that_leaves_a_unit_not_enabled_is_rolled_back() {
    let lab = Lab::new("enable-rollback");
    lab.install_old();
    lab.binaries("new", NEW);
    fs::write(lab.root.join("lose-enable"), "").unwrap();
    let r = lab.upgrade();
    assert_ne!(r.status, 0, "{r:#?}");
    assert!(
        r.stderr.contains(
            "health check FAILED: northnarrow-watchdog.service is disabled (systemctl is-enabled) — the next boot would start no agent"
        ),
        "{r:#?}"
    );
    assert!(!r.stdout.contains("UPGRADE complete"), "{r:#?}");
    assert_eq!(
        fs::read(lab.root.join("bin/northnarrow-agent")).unwrap(),
        fs::read(lab.case.join("old/target/release/northnarrow-agent")).unwrap(),
        "the old release restored"
    );
    for u in ["northnarrow-agent", "northnarrow-watchdog"] {
        // the review of #497 (D5, M9): enabled for every boot, not the
        // runtime only
        assert_eq!(
            fs::read_to_string(lab.root.join(format!("enabled.{u}")))
                .unwrap_or_default()
                .trim(),
            "enabled",
            "{u} enabled again: {r:#?}"
        );
    }
    let rows = lab.audit_rows("upgrade_rolled_back");
    assert_eq!(rows.len(), 1, "{r:#?}");
    assert_eq!(rows[0]["extra"]["stage"], "health_check");
}

/// The review of #497 (D5, M7): the rollback enables again only what was
/// enabled before the run — a unit the operator disabled stays disabled.
/// (Units not running: no preflight, the switch fails and is rolled back.)
#[test]
fn a_rollback_leaves_a_unit_the_operator_disabled_disabled() {
    let lab = Lab::new("enable-operator");
    lab.install_old();
    for u in ["northnarrow-agent", "northnarrow-watchdog"] {
        fs::write(lab.root.join(format!("state.{u}")), "inactive\n").unwrap();
        fs::write(lab.root.join("cg").join(u).join("cgroup.procs"), "").unwrap();
    }
    let _ = fs::remove_dir_all(lab.root.join("pins"));
    assert!(lab.systemctl(&["disable", "northnarrow-watchdog.service"]));
    lab.binaries("new", NEW);
    fs::write(lab.root.join("fail-daemon-reload"), "").unwrap();
    let r = lab.install("new", &["--source-tree"]);
    assert_ne!(r.status, 0, "{r:#?}");
    assert!(
        r.stderr.contains("UPGRADE FAILED") || r.stderr.contains("rolling back"),
        "{r:#?}"
    );
    assert_eq!(
        fs::read_to_string(lab.root.join("enabled.northnarrow-agent"))
            .unwrap_or_default()
            .trim(),
        "enabled",
        "{r:#?}"
    );
    assert!(
        !lab.root.join("enabled.northnarrow-watchdog").exists(),
        "the operator's disable kept: {r:#?}"
    );
}

/// Lab PR 220 (P0 C-45 / G-07 / TD-09): the new agent starts but never logs
/// that its hooks attached. The upgrade does not end there: the new units
/// are stopped through the new agent's own window, every file the upgrade
/// touched is back byte for byte (mode and mtime too) and nothing it
/// created is left, the previous agent and watchdog run again and pass the
/// same health check, and the previous agent signs `upgrade_rolled_back`
/// with what failed. Exit 3, the reason on stderr and in the system log.
#[test]
fn an_upgrade_that_fails_its_health_check_is_rolled_back_byte_for_byte() {
    let lab = Lab::new("health-rollback");
    lab.install_old();
    let before = lab.snapshot();
    assert!(
        before.contains_key("bin/northnarrow-agent"),
        "{:?}",
        before.keys()
    );
    lab.binaries(
        "new",
        Build {
            agent_fail: "health",
            ..NEW
        },
    );
    let r = lab.upgrade();
    assert_eq!(r.status, 3, "{r:#?}");
    let diff = snapshot_diff(&before, &lab.snapshot());
    assert!(
        diff.is_empty(),
        "not restored byte for byte: {diff:#?}\n{r:#?}"
    );
    assert_eq!(
        started(&r, "northnarrow-agent"),
        ["northnarrow-agent 0.0.2", "northnarrow-agent 0.0.1"],
        "{r:#?}"
    );
    assert_eq!(
        started(&r, "northnarrow-watchdog"),
        ["northnarrow-watchdog 0.0.2", "northnarrow-watchdog 0.0.1"]
    );
    assert_eq!(
        r.called(GRANT),
        2,
        "the old agent's window, then the new one's: {r:#?}"
    );
    assert_eq!(lab.state("northnarrow-agent"), "active");
    assert_eq!(lab.state("northnarrow-watchdog"), "active");
    let rows = lab.audit_rows("upgrade_rolled_back");
    assert_eq!(rows.len(), 1, "{r:#?}");
    let e = &rows[0]["extra"];
    assert_eq!(e["stage"], "health_check");
    assert_eq!(e["failed_version"], "northnarrow-agent 0.0.2");
    assert_eq!(e["restored_version"], "northnarrow-agent 0.0.1");
    assert!(
        e["reason"]
            .as_str()
            .unwrap()
            .contains("logged no 'anti-tamper: all LSM hooks attached'"),
        "{e}"
    );
    assert!(!lab.root.join("run/upgrade-rolled-back.json").exists());
    for want in [
        "UPGRADE FAILED — health_check",
        "UPGRADE ROLLED BACK",
        "running again: northnarrow-agent 0.0.1",
        "signed record: upgrade_rolled_back",
    ] {
        assert!(r.stderr.contains(want), "{want}: {r:#?}");
    }
    let logged = lab.logged();
    assert!(
        logged.contains("-p auth.err -t northnarrow-install -- upgrade northnarrow-agent 0.0.1 -> northnarrow-agent 0.0.2 failed"),
        "{logged}"
    );
    assert!(lab.txn_entries().is_empty(), "{:?}", lab.txn_entries());
}

/// A failure at each stage after the stop rolls back: the previous BPF
/// programs not unloading (stop), the watchdog unit's rename failing after
/// the binaries and the agent unit were switched — the finding's own case —
/// and a failing `daemon-reload` (switch), a new agent or watchdog that does
/// not start (reported at `health_check`: the start step does not check
/// what it started), and health checks that do not pass: a deny-hook
/// shortfall, a forged health line in another event… each ends with the
/// previous files byte for byte, the previous units healthy, exit 3 and the
/// stage in the signed record. (A new agent that runs without answering on
/// its socket keeps its window shut: that is the exit-4 path, not covered
/// here; the fake agent's `socket` mode is not exercised yet.)
#[test]
fn a_failure_at_each_stage_is_rolled_back() {
    type Arm = fn(&Lab);
    let cases: [(&str, &str, Build, Arm); 7] = [
        ("stop", "stop", NEW, |l| {
            fs::write(l.root.join("progs-stuck"), "").unwrap()
        }),
        ("switch-unit", "switch", NEW, |l| {
            fs::write(l.root.join("fail-mv"), "units/northnarrow-watchdog.service").unwrap()
        }),
        ("switch-reload", "switch", NEW, |l| {
            fs::write(l.root.join("fail-daemon-reload"), "").unwrap()
        }),
        (
            "agent-start",
            "health_check",
            Build {
                agent_fail: "start",
                ..NEW
            },
            |_| {},
        ),
        (
            "watchdog-start",
            "health_check",
            Build {
                watchdog_fail: "start",
                ..NEW
            },
            |_| {},
        ),
        (
            "deny-shortfall",
            "health_check",
            Build {
                agent_fail: "degraded",
                ..NEW
            },
            |_| {},
        ),
        (
            "forged-line",
            "health_check",
            Build {
                agent_fail: "forged",
                ..NEW
            },
            |_| {},
        ),
    ];
    for (case, stage, build, arm) in cases {
        let lab = Lab::new(&format!("stage-{case}"));
        lab.install_old();
        let before = lab.snapshot();
        lab.binaries("new", build);
        arm(&lab);
        if case == "stop" {
            // the drain fails with the old units stopped; the next start
            // must not find the programs stuck
            let r = lab.upgrade();
            assert_eq!(r.status, 3, "{case}: {r:#?}");
            assert!(r.stderr.contains("did not unload"), "{case}: {r:#?}");
        } else {
            let r = lab.upgrade();
            assert_eq!(r.status, 3, "{case}: {r:#?}");
            assert_eq!(
                started(&r, "northnarrow-agent").last().map(String::as_str),
                Some("northnarrow-agent 0.0.1"),
                "{case}: {r:#?}"
            );
            // the unit that did not start is named, whatever else is not
            // active beside it (lab, 21/10: a watchdog left "activating" by
            // its agent was named alone)
            if case == "agent-start" {
                assert!(
                    r.stderr.contains("health check FAILED: ")
                        && r.stderr.contains("northnarrow-agent.service is "),
                    "{case}: {r:#?}"
                );
            }
        }
        let diff = snapshot_diff(&before, &lab.snapshot());
        assert!(diff.is_empty(), "{case}: {diff:#?}");
        assert_eq!(lab.state("northnarrow-agent"), "active", "{case}");
        assert_eq!(lab.state("northnarrow-watchdog"), "active", "{case}");
        let rows = lab.audit_rows("upgrade_rolled_back");
        assert_eq!(rows.len(), 1, "{case}");
        assert_eq!(rows[0]["extra"]["stage"], stage, "{case}");
        assert!(lab.txn_entries().is_empty(), "{case}");
    }
    // what the health check said, for the shortfall and the forged line
    let lab = Lab::new("stage-reasons");
    lab.install_old();
    lab.binaries(
        "new",
        Build {
            agent_fail: "degraded",
            ..NEW
        },
    );
    let r = lab.upgrade();
    assert!(
        r.stderr
            .contains("17 of 18 deny hooks attached (DENY HOOK SHORTFALL)"),
        "{r:#?}"
    );
}

/// The new agent pins its hooks and dies (a refused boot), so nothing can
/// open its window: the files stay protected and the rollback cannot finish
/// on the spot. It says so (exit 4, auth.crit), and leaves rollback.sh;
/// after the reboot it asks for (no pin root, no unit running) that script
/// restores the previous files byte for byte, starts the previous units,
/// checks them, and the previous agent signs the record.
#[test]
fn a_rollback_the_new_hooks_block_is_finished_by_rollback_sh() {
    let lab = Lab::new("stuck");
    lab.install_old();
    let before = lab.snapshot();
    lab.binaries(
        "new",
        Build {
            agent_fail: "start-pinned",
            ..NEW
        },
    );
    let r = lab.upgrade();
    assert_eq!(r.status, 4, "{r:#?}");
    assert!(r.stderr.contains("ROLLBACK INCOMPLETE"), "{r:#?}");
    assert!(lab.logged().contains("-p auth.crit -t northnarrow-install"));
    let txn = lab.txn_entries();
    assert_eq!(txn.len(), 1, "{txn:?}");
    let script = txn[0].join("rollback.sh");
    assert!(r.stderr.contains(&script.display().to_string()), "{r:#?}");
    assert!(
        lab.root.join("pins").exists(),
        "the new agent's hooks are still pinned"
    );

    // the reboot: bpffs and every process gone
    fs::remove_dir_all(lab.root.join("pins")).unwrap();
    for u in ["northnarrow-agent", "northnarrow-watchdog"] {
        fs::write(lab.root.join(format!("state.{u}")), "inactive\n").unwrap();
        fs::write(lab.root.join("cg").join(u).join("cgroup.procs"), "").unwrap();
    }
    let text = fs::read_to_string(&script).unwrap();
    assert_eq!(text.matches("[[ $EUID != 0 ]]").count(), 1, "{text}");
    let mut cmd = Command::new("bash");
    cmd.arg("-c").arg(text.replace("[[ $EUID != 0 ]]", "false"));
    lab.env(&mut cmd);
    let r2 = lab.finish(cmd);
    assert_eq!(r2.status, 0, "{r2:#?}");
    assert!(
        r2.stdout.contains("rolled back to northnarrow-agent 0.0.1"),
        "{r2:#?}"
    );
    assert_eq!(
        started(&r2, "northnarrow-agent"),
        ["northnarrow-agent 0.0.1"],
        "{r2:#?}"
    );
    let diff = snapshot_diff(&before, &lab.snapshot());
    assert!(diff.is_empty(), "{diff:#?}");
    let rows = lab.audit_rows("upgrade_rolled_back");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["extra"]["stage"], "health_check");

    // run while a unit is up, it refuses and changes nothing
    let lab = Lab::new("stuck-refuse");
    lab.install_old();
    lab.binaries(
        "new",
        Build {
            agent_fail: "start-pinned",
            ..NEW
        },
    );
    assert_eq!(lab.upgrade().status, 4);
    let script = lab.txn_entries()[0].join("rollback.sh");
    let mut cmd = Command::new("bash");
    cmd.arg("-c").arg(
        fs::read_to_string(&script)
            .unwrap()
            .replace("[[ $EUID != 0 ]]", "false"),
    );
    lab.env(&mut cmd);
    let r3 = lab.finish(cmd);
    assert_eq!(r3.status, 1, "{r3:#?}");
    assert!(r3.stderr.contains("reboot"), "{r3:#?}");
}

/// The copies are checked against the hashes taken before the stop: a copy
/// changed during the run (here by the new agent's start) is not put back
/// as if it were the previous file — the rollback stops at exit 4 and names
/// it.
#[test]
fn a_backup_changed_during_the_run_is_not_restored_silently() {
    let lab = Lab::new("tampered-backup");
    lab.install_old();
    lab.binaries(
        "new",
        Build {
            agent_fail: "tamper-backup",
            ..NEW
        },
    );
    let r = lab.upgrade();
    assert_eq!(r.status, 4, "{r:#?}");
    assert!(
        r.stderr
            .contains("a restored file is not the one backed up"),
        "{r:#?}"
    );
    assert!(r.stderr.contains("bin/northnarrow-agent: FAILED"), "{r:#?}");
    assert!(r.stderr.contains("ROLLBACK INCOMPLETE"), "{r:#?}");
}

/// A good upgrade: the new binaries and units switched, the new units pass
/// the health check, nothing of the transaction left, exit 0. An agent with
/// every deny hook but not every observe hook passes with a WARNING.
#[test]
fn a_healthy_upgrade_commits() {
    for (case, fail) in [("good", "none"), ("observe-shortfall", "observe")] {
        let lab = Lab::new(&format!("commit-{case}"));
        lab.install_old();
        lab.binaries(
            "new",
            Build {
                agent_fail: fail,
                ..NEW
            },
        );
        let r = lab.upgrade();
        assert_eq!(r.status, 0, "{case}: {r:#?}");
        assert!(
            r.stdout.contains("UPGRADE complete — health check passed"),
            "{case}: {r:#?}"
        );
        assert_eq!(
            fs::read(lab.root.join("bin/northnarrow-agent")).unwrap(),
            fs::read(lab.case.join("new/target/release/northnarrow-agent")).unwrap()
        );
        assert!(
            fs::read_to_string(lab.root.join("units/northnarrow-agent.service"))
                .unwrap()
                .contains("a newer release")
        );
        assert_eq!(
            started(&r, "northnarrow-agent"),
            ["northnarrow-agent 0.0.2"]
        );
        assert!(lab.txn_entries().is_empty(), "{case}");
        assert!(lab.audit_rows("upgrade_rolled_back").is_empty());
        let leftovers: Vec<String> = lab
            .snapshot()
            .keys()
            .filter(|k| k.ends_with(".nn-new") || k.ends_with(".nn-rollback"))
            .cloned()
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        assert_eq!(
            r.stderr.contains("not every observe hook"),
            fail == "observe",
            "{case}: {r:#?}"
        );
    }
}

/// The restored agent may predate the marker: nothing signs the rollback,
/// the report says so, and the marker does not wait for a later agent.
#[test]
fn an_agent_older_than_the_marker_is_reported_not_trusted() {
    let lab = Lab::new("old-agent-no-marker");
    lab.binaries(
        "old",
        Build {
            reads_marker: false,
            ..OLD
        },
    );
    lab.install_old();
    lab.binaries(
        "new",
        Build {
            agent_fail: "health",
            ..NEW
        },
    );
    let r = lab.upgrade();
    assert_eq!(r.status, 3, "{r:#?}");
    assert!(
        r.stderr
            .contains("signed record: none: the restored agent does not read"),
        "{r:#?}"
    );
    assert!(lab.audit_rows("upgrade_rolled_back").is_empty());
    assert!(!lab.root.join("run/upgrade-rolled-back.json").exists());
}

/// An upgrade over running units without --grant-key is refused before
/// anything is stopped or changed: a rollback needs the new agent's window.
#[test]
fn an_upgrade_without_a_key_changes_nothing() {
    let lab = Lab::new("no-key");
    lab.install_old();
    let before = lab.snapshot();
    let r = lab.install("new", &["--source-tree", "--upgrade"]);
    assert_eq!(r.status, 1, "{r:#?}");
    assert!(r.stderr.contains("--upgrade needs --grant-key"), "{r:#?}");
    assert!(snapshot_diff(&before, &lab.snapshot()).is_empty());
    assert_eq!(lab.state("northnarrow-agent"), "active");
    assert!(
        r.calls.iter().all(|c| !c.starts_with("systemctl kill")),
        "{r:#?}"
    );
    assert!(lab.txn_entries().is_empty());
}

// ── Lab PR 220: provenance verification blocks by default ───────────────

/// A release tree `name` next to its tarball and SHA256SUMS, made the way
/// mk-tarball.sh makes them, from the lab's `new` tree.
fn release(lab: &Lab, name: &str) -> PathBuf {
    let rel = lab.case.join("rel");
    let tree = rel.join(name);
    let _ = fs::remove_dir_all(&rel);
    fs::create_dir_all(&rel).unwrap();
    let ok = Command::new("cp")
        .arg("-a")
        .arg(lab.case.join("new"))
        .arg(&tree)
        .status()
        .unwrap()
        .success();
    assert!(ok);
    let sh = |script: &str| {
        let out = Command::new("bash")
            .arg("-c")
            .arg(script)
            .current_dir(&rel)
            .output()
            .unwrap();
        assert!(out.status.success(), "{script}: {out:?}");
    };
    sh(&format!(
        "cd {name} && find . -type f ! -name MANIFEST.sha256 -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > MANIFEST.sha256"
    ));
    sh(&format!(
        "tar -czf {name}.tar.gz {name} && sha256sum {name}.tar.gz > SHA256SUMS"
    ));
    tree
}

impl Lab {
    /// install.sh from a release tree (absolute path), a fresh install.
    fn install_release(&self, tree: &Path, args: &[&str]) -> Run {
        let text = read("deploy/install.sh").replace("\nrequire_root\n", "\n");
        let mut cmd = script_command(&self.case, &text);
        cmd.args(args)
            .args([
                "--without-nftables",
                "--admin-key-out",
                self.root.join("admin.key").to_str().unwrap(),
            ])
            .env("REPO_ROOT", tree)
            .env("TARGET_DIR", tree.join("target/release"));
        self.env(&mut cmd);
        self.finish(cmd)
    }

    fn manifest(&self) -> serde_json::Value {
        serde_json::from_str(
            &fs::read_to_string(self.root.join("etc/install-manifest.json")).unwrap(),
        )
        .unwrap()
    }

    fn installed(&self) -> bool {
        self.root.join("bin/northnarrow-agent").exists()
    }
}

const NAME: &str = "northnarrow-0.0.2-x86_64-linux";

/// Static review of `baf4c25` P0 C-45 / G-07: a release tree with its
/// tarball and an unsigned SHA256SUMS used to install as `checksums` when
/// no attestation verified. It is refused now, before anything is copied —
/// the reason on stderr — unless --allow-unverified, which is a WARNING on
/// stderr, a line in the system log (auth.warning) and `verify_override` in
/// the install manifest with the level reached and why the attestation
/// failed. The former --allow-manifest-only still accepts, recorded as
/// given; --require-attestation is the default, and contradicts the flag.
#[test]
fn an_unattested_release_is_refused_unless_allowed_and_the_flag_is_logged() {
    let lab = Lab::new("provenance");
    let tree = release(&lab, NAME);

    let r = lab.install_release(&tree, &[]);
    assert_eq!(r.status, 1, "{r:#?}");
    assert!(r.stdout.contains("tarball matches SHA256SUMS"), "{r:#?}");
    assert!(
        r.stderr.contains("REFUSED — the release's SLSA provenance attestation did not verify (no attestation verifier"),
        "{r:#?}"
    );
    assert!(r.stderr.contains("--allow-unverified"), "{r:#?}");
    assert!(!lab.installed(), "refused before anything is copied");
    assert!(!lab.logged().contains("auth.warning"), "{}", lab.logged());

    let r = lab.install_release(&tree, &["--allow-unverified"]);
    assert_eq!(r.status, 0, "{r:#?}");
    assert!(lab.installed());
    let m = lab.manifest();
    assert_eq!(m["provenance"], "checksums");
    assert_eq!(m["verify_override"], "--allow-unverified");
    assert_eq!(m["attestation"]["verified"], false);
    assert!(m["attestation"]["failure"]
        .as_str()
        .unwrap()
        .starts_with("no attestation verifier"));
    assert!(
        r.stderr.contains(
            "WARNING: --allow-unverified — the release's provenance attestation did not verify"
        ),
        "{r:#?}"
    );
    let logged = lab.logged();
    assert!(
        logged.contains("-p auth.warning -t northnarrow-install -- --allow-unverified — the release's provenance attestation did not verify (no attestation verifier"),
        "{logged}"
    );

    // the former name of the flag, recorded as given
    let lab = Lab::new("provenance-legacy");
    let tree = release(&lab, NAME);
    let r = lab.install_release(&tree, &["--allow-manifest-only"]);
    assert_eq!(r.status, 0, "{r:#?}");
    assert_eq!(lab.manifest()["verify_override"], "--allow-manifest-only");

    // --require-attestation is the default and contradicts the opt-out
    let r = lab.install_release(&tree, &["--require-attestation", "--allow-unverified"]);
    assert_eq!(r.status, 2, "{r:#?}");

    // no tarball next to the tree: refused at `manifest`
    let lab = Lab::new("provenance-no-tarball");
    let tree = release(&lab, NAME);
    fs::remove_file(lab.case.join(format!("rel/{NAME}.tar.gz"))).unwrap();
    let r = lab.install_release(&tree, &[]);
    assert_eq!(r.status, 1, "{r:#?}");
    assert!(
        r.stderr
            .contains("did not verify (no tarball next to the tree)"),
        "{r:#?}"
    );
    let r = lab.install_release(&tree, &["--allow-unverified"]);
    assert_eq!(r.status, 0, "{r:#?}");
    assert_eq!(lab.manifest()["provenance"], "manifest");
}

/// gh verifies the tarball against the release-tag identity: `attested`,
/// no flag needed. A gh that fails is a refusal with what gh said. A tree
/// edited after extraction, with its MANIFEST.sha256 rewritten to match,
/// next to a genuine tarball, is refused whatever the flags: the tree must
/// be the tarball's.
#[test]
fn an_attested_release_installs_and_a_tree_not_from_its_tarball_does_not() {
    let lab = Lab::new("attested");
    let tree = release(&lab, NAME);
    write_exec(
        &lab.case.join("stub/gh"),
        r#"echo "gh $*" >> "$NN_TEST_DIR/gh-calls"
[ "$1 $2" = "attestation --help" ] && exit 0
[ -e "$NN_TEST_DIR/gh-refuses" ] && { echo "verification failed: no matching attestation for the tag identity"; exit 1; }
exit 0"#,
    );
    let r = lab.install_release(&tree, &[]);
    assert_eq!(r.status, 0, "{r:#?}");
    assert_eq!(lab.manifest()["provenance"], "attested");
    assert!(lab.manifest()["verify_override"].is_null());
    let gh = fs::read_to_string(lab.root.join("gh-calls")).unwrap();
    assert!(
        gh.contains("attestation verify")
            && gh.contains("--cert-identity-regex ^https://github\\.com/northnarrow/northnarrow-new/\\.github/workflows/release\\.yml@refs/tags/v")
            && gh.contains("--deny-self-hosted-runners"),
        "{gh}"
    );

    let lab = Lab::new("attest-refused");
    let tree = release(&lab, NAME);
    fs::copy(
        lab.case.join("../lab-attested/stub/gh"),
        lab.case.join("stub/gh"),
    )
    .unwrap();
    fs::write(lab.root.join("gh-refuses"), "").unwrap();
    let r = lab.install_release(&tree, &[]);
    assert_eq!(r.status, 1, "{r:#?}");
    assert!(r.stderr.contains("gh attestation verify FAILED"), "{r:#?}");
    assert!(
        r.stderr
            .contains("no matching attestation for the tag identity"),
        "{r:#?}"
    );
    assert!(
        r.stderr
            .contains("did not verify (gh attestation verify failed)"),
        "{r:#?}"
    );
    assert!(!lab.installed());

    // edited after extraction, manifest rewritten: not the tarball's tree
    let lab = Lab::new("not-the-tarballs");
    let tree = release(&lab, NAME);
    append(&tree.join("configs/fim-paths.v1"), "/nn-test-edited\n");
    let out = Command::new("bash")
        .arg("-c")
        .arg("find . -type f ! -name MANIFEST.sha256 -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > MANIFEST.sha256")
        .current_dir(&tree)
        .output()
        .unwrap();
    assert!(out.status.success());
    for args in [&[][..], &["--allow-unverified"][..]] {
        let r = lab.install_release(&tree, args);
        assert_eq!(r.status, 1, "{args:?}: {r:#?}");
        assert!(r.stderr.contains("is not the one in"), "{r:#?}");
        assert!(!lab.installed());
    }
}

/// The lab's path: a build from source (no MANIFEST.sha256) installs with
/// --source-tree as before, or with --allow-unverified; refused with
/// neither. Either flag is logged and recorded.
#[test]
fn a_source_tree_installs_with_either_flag_and_the_flag_is_logged() {
    let lab = Lab::new("source-tree-refused");
    let r = lab.install("new", &[]);
    assert_eq!(r.status, 1, "{r:#?}");
    assert!(
        r.stderr.contains("--source-tree or --allow-unverified"),
        "{r:#?}"
    );
    assert!(!lab.installed());
    for flag in ["--source-tree", "--allow-unverified"] {
        let lab = Lab::new(&format!("source-tree{flag}"));
        let r = lab.install("new", &[flag]);
        assert_eq!(r.status, 0, "{flag}: {r:#?}");
        let m = lab.manifest();
        assert_eq!(m["provenance"], "source-tree");
        assert_eq!(m["verify_override"], flag);
        assert!(
            lab.logged().contains(&format!(
                "-p auth.warning -t northnarrow-install -- {flag} — no MANIFEST.sha256"
            )),
            "{}",
            lab.logged()
        );
    }
    // the lab installs with --source-tree (deploy/lab/nn-lab.sh install)
    let lab_sh = read("deploy/lab/nn-lab.sh");
    assert!(
        lab_sh.contains("sudo ./deploy/install.sh --source-tree && sudo systemctl daemon-reload")
    );
}

/// `install.sh --help` (no root needed) names the opt-out, the rollback's
/// exit codes and the key an upgrade needs.
#[test]
fn install_help_names_the_new_flags() {
    let out = Command::new("bash")
        .arg(repo_root().join("deploy/install.sh"))
        .arg("--help")
        .output()
        .expect("bash runs");
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    for want in [
        "--allow-unverified",
        "exit 3; 4 when",
        "required by --upgrade",
        "--require-attestation: the default",
    ] {
        assert!(text.contains(want), "{want}: {text}");
    }
}

// ── Lab PR 220: the package hooks report an unhealthy upgrade ───────────

impl Lab {
    /// install.sh --package-configure (or --package-verify) on the new
    /// package's files, after the pre-unpack hook stopped `listed`.
    fn package(&self, args: &[&str]) -> Run {
        let text = read("deploy/install.sh").replace("\nrequire_root\n", "\n");
        let t = self.case.join("new");
        let mut cmd = script_command(&self.case, &text);
        cmd.args(args).env("REPO_ROOT", &t);
        self.env(&mut cmd);
        self.finish(cmd)
    }

    /// The new package unpacked over a stopped install: its binaries and
    /// units in place, the restart list naming both units.
    fn unpacked(&self) {
        let r = self.install("new", &["--source-tree"]);
        assert_eq!(r.status, 0, "{r:#?}");
        fs::write(
            self.root.join("pkg-restart"),
            "northnarrow-watchdog\nnorthnarrow-agent\n",
        )
        .unwrap();
    }
}

/// The short re-check of #497 (RB1): a package's configure step runs the
/// installed agent's drop-in check as a warning — each one named, the
/// remedy given, nothing moved, the hook not failed.
#[test]
fn the_package_configure_step_warns_of_the_drop_ins_the_agent_judges_harmful() {
    let lab = Lab::new("pkg-dropins");
    lab.unpacked();
    let d = "/etc/systemd/system/northnarrow-agent.service.d";
    fs::write(
        lab.root.join("own-dropins"),
        format!("would move {d}/60-env.conf: found by the installer's check, EnvironmentFile=/etc/default/nn lies outside /etc/northnarrow/\n"),
    )
    .unwrap();
    let _ = fs::remove_file(lab.root.join("own-dropins.calls"));
    let r = lab.package(&["--package-configure"]);
    assert_eq!(r.status, 0, "the hook never fails on it: {r:#?}");
    for want in [
        "install.sh: WARNING: the drop-in directories of the agent's own units hold drop-ins",
        &format!("install.sh:   {d}/60-env.conf: found by the installer's check, EnvironmentFile=/etc/default/nn"),
        "UPGRADE_NOTES_WAVE4.md section 9",
    ] {
        assert!(r.stderr.contains(want), "{want}: {r:#?}");
    }
    assert_eq!(
        fs::read_to_string(lab.root.join("own-dropins.calls")).unwrap(),
        "own-dropins check\n",
        "checked once, never asked to move"
    );
    assert!(r.stdout.contains("health check passed"), "{r:#?}");
}

/// External audit DEP-010 covered a failed operation; lab PR 220 covers the
/// one that "succeeds" with an agent that does not protect the host. The
/// configure step (deb postinst) checks the units it restarted: an
/// unhealthy one fails the hook — named on stderr and at auth.err, the
/// restart list kept for `dpkg --configure -a` — and a healthy one passes
/// and drops the list. The rpm defers the check to %posttrans
/// (--package-verify), after its whole transaction.
#[test]
fn the_package_configure_step_fails_on_an_unhealthy_upgrade() {
    let lab = Lab::new("pkg-unhealthy");
    lab.binaries(
        "new",
        Build {
            agent_fail: "health",
            ..NEW
        },
    );
    lab.unpacked();
    let r = lab.package(&["--package-configure"]);
    assert_eq!(r.status, 1, "{r:#?}");
    assert!(r.stderr.contains("did not pass its health check"), "{r:#?}");
    assert!(r.stderr.contains("§6.2"), "{r:#?}");
    assert!(lab
        .logged()
        .contains("-p auth.err -t northnarrow-pkg -- the upgraded NorthNarrow did not pass"));
    assert!(
        lab.root.join("pkg-restart").exists(),
        "kept for the next attempt"
    );

    let lab = Lab::new("pkg-healthy");
    lab.unpacked();
    let r = lab.package(&["--package-configure"]);
    assert_eq!(r.status, 0, "{r:#?}");
    assert!(r.stdout.contains("health check passed"), "{r:#?}");
    assert!(!lab.root.join("pkg-restart").exists());

    // rpm: %post defers, %posttrans checks
    for (case, build, status) in [
        (
            "rpm-unhealthy",
            Build {
                watchdog_fail: "noregister",
                ..NEW
            },
            1,
        ),
        ("rpm-healthy", NEW, 0),
    ] {
        let lab = Lab::new(case);
        lab.binaries("new", build);
        lab.unpacked();
        let r = lab.package(&["--package-configure", "--defer-health-check"]);
        assert_eq!(r.status, 0, "{case}: {r:#?}");
        assert!(r.stdout.contains("%posttrans"), "{case}: {r:#?}");
        assert!(lab.root.join("pkg-restart").exists(), "{case}");
        let r = lab.package(&["--package-verify"]);
        assert_eq!(r.status, status, "{case}: {r:#?}");
        assert_eq!(lab.root.join("pkg-restart").exists(), status != 0, "{case}");
        if status != 0 {
            assert!(
                r.stderr
                    .contains("logged no 'watchdog PID registered in PROTECTED_PIDS'"),
                "{r:#?}"
            );
        }
    }
    // nothing restarted (a first install): nothing checked
    let lab = Lab::new("rpm-first");
    let r = lab.package(&["--package-verify"]);
    assert_eq!(r.status, 0, "{r:#?}");
    assert!(r.calls.is_empty(), "{r:#?}");
    let r = lab.package(&["--defer-health-check"]);
    assert_eq!(r.status, 2, "{r:#?}");
}

/// The hooks wire it: the deb configure step checks, the rpm %post defers
/// to a %posttrans that runs --package-verify, and mk-packages.sh puts
/// that scriptlet in the .rpm only.
#[test]
fn the_package_scripts_run_the_health_check() {
    let post = read("deploy/release/pkg/postinst.sh");
    let deb = section(
        "deploy/release/pkg/postinst.sh",
        "    configure)\n",
        "    1|2)\n",
    );
    assert!(deb.contains("install.sh --package-configure\n"), "{deb}");
    let rpm = section(
        "deploy/release/pkg/postinst.sh",
        "    1|2)\n",
        "        ;;\n    abort-",
    );
    assert!(
        rpm.contains("--package-configure --defer-health-check"),
        "{rpm}"
    );
    assert!(post.contains("restart_stopped || exit 1"));
    let posttrans = read("deploy/release/pkg/posttrans.sh");
    assert!(
        posttrans.contains("install.sh --package-verify || exit 1"),
        "{posttrans}"
    );
    let mk = read("deploy/release/mk-packages.sh");
    assert!(mk.contains("for s in preinst postinst prerm postrm posttrans; do"));
    assert!(mk.contains("%posttrans -p /bin/sh\n$(body posttrans)"));
    assert!(
        mk.contains("for s in preinst postinst prerm postrm; do install -m 0755"),
        "the .deb carries no posttrans"
    );
    let wf = read(".github/workflows/release.yml");
    assert!(wf.contains("grep -c 'scriptlet (using /bin/sh)')\" = 5"));
    for s in ["postinst.sh", "posttrans.sh"] {
        let out = Command::new("sh")
            .arg("-n")
            .arg(repo_root().join("deploy/release/pkg").join(s))
            .output()
            .unwrap();
        assert!(out.status.success(), "{s}: {out:?}");
    }
}

/// R14a: run `body` (a block of an install script) under bash with stub
/// `getent`, `id`, `useradd`, `userdel` that record their calls;
/// `present`: the accounts the host already has, `tools`: whether
/// useradd/userdel exist. An account present is the one install.sh
/// creates (uid and gid 990, nologin, a locked password, its own group)
/// unless [`accounts_run_as`] gives its entries.
fn accounts_run(case: &str, body: &str, present: &[&str], tools: bool) -> (Run, Vec<String>) {
    let entries: Vec<(&str, Account)> = present.iter().map(|u| (*u, Account::default())).collect();
    accounts_run_as(case, body, &entries, tools)
}

/// An existing account's entries, for the stubs (review of #480, F11).
#[derive(Clone)]
struct Account {
    uid: &'static str,
    gid: &'static str,
    shell: &'static str,
    /// The shadow file's password field (`None`: no shadow entry).
    shadow: Option<&'static str>,
    /// `id -G` (`None`: the gid alone).
    groups: Option<&'static str>,
}

impl Default for Account {
    fn default() -> Self {
        Account {
            uid: "990",
            gid: "990",
            shell: "/usr/sbin/nologin",
            shadow: Some("!"),
            groups: None,
        }
    }
}

/// [`accounts_run_as`] with the running agent's pid (`None`: no agent) and
/// the processes `/proc` holds: (pid, uid, parent).
fn accounts_run_procs(
    case: &str,
    body: &str,
    present: &[(&str, Account)],
    agent: Option<u32>,
    procs: &[(u32, u32, u32)],
) -> (Run, Vec<String>) {
    let mut setup = String::new();
    if let Some(a) = agent {
        setup.push_str(&format!("echo {a} > \"$NN_TEST_DIR/agent.pid\"\n"));
    }
    for (pid, uid, ppid) in procs {
        setup.push_str(&format!(
            "mkdir -p \"$NN_TEST_DIR/proc/{pid}\"\n\
             printf 'Name:\\tx\\nPPid:\\t{ppid}\\nUid:\\t{uid}\\t{uid}\\t{uid}\\t{uid}\\n' \
             > \"$NN_TEST_DIR/proc/{pid}/status\"\n"
        ));
    }
    accounts_run_as(case, &format!("{setup}{body}"), present, true)
}

fn accounts_run_as(
    case: &str,
    body: &str,
    present: &[(&str, Account)],
    tools: bool,
) -> (Run, Vec<String>) {
    let dir = case_dir(case);
    let stub = dir.join("stub");
    fs::create_dir_all(&stub).unwrap();
    for (u, a) in present {
        fs::write(
            dir.join(format!("user.{u}")),
            format!("{u}:x:{}:{}::/nonexistent:{}\n", a.uid, a.gid, a.shell),
        )
        .unwrap();
        if let Some(pw) = a.shadow {
            fs::write(
                dir.join(format!("shadow.{u}")),
                format!("{u}:{pw}:19000::::::\n"),
            )
            .unwrap();
        }
        fs::write(
            dir.join(format!("groups.{u}")),
            format!("{}\n", a.groups.unwrap_or(a.gid)),
        )
        .unwrap();
    }
    fs::write(dir.join("login.defs"), "UID_MIN 1000\nGID_MIN 1000\n").unwrap();
    fs::create_dir_all(dir.join("proc")).unwrap();
    write_exec(
        &stub.join("systemctl"),
        r#"[ -e "$NN_TEST_DIR/agent.pid" ] && cat "$NN_TEST_DIR/agent.pid""#,
    );
    write_exec(
        &stub.join("getent"),
        r#"case $1 in
  passwd) if [ $# = 1 ]; then cat "$NN_TEST_DIR"/user.* 2>/dev/null; true; else
            [ -e "$NN_TEST_DIR/user.$2" ] && cat "$NN_TEST_DIR/user.$2"; fi ;;
  shadow) [ -e "$NN_TEST_DIR/shadow.$2" ] && cat "$NN_TEST_DIR/shadow.$2" ;;
  *) exit 2 ;;
esac"#,
    );
    write_exec(
        &stub.join("id"),
        r#"[ "$1" = -G ] && [ -e "$NN_TEST_DIR/groups.$2" ] && cat "$NN_TEST_DIR/groups.$2""#,
    );
    // the tools the check reads with
    for t in ["awk", "cut", "cat"] {
        if let Some(p) = ["/usr/bin", "/bin"]
            .iter()
            .map(|d| Path::new(d).join(t))
            .find(|p| p.exists())
        {
            let _ = std::os::unix::fs::symlink(p, stub.join(t));
        }
    }
    if tools {
        write_exec(
            &stub.join("useradd"),
            r#"echo "useradd $*" >> "$NN_TEST_DIR/calls"; for u; do :; done; echo "$u:x:991:991::/nonexistent:/usr/sbin/nologin" > "$NN_TEST_DIR/user.$u""#,
        );
        write_exec(
            &stub.join("userdel"),
            r#"echo "userdel $*" >> "$NN_TEST_DIR/calls"; rm -f "$NN_TEST_DIR/user.$1" "$NN_TEST_DIR/shadow.$1" "$NN_TEST_DIR/groups.$1""#,
        );
    }
    // `command -v` must not find the host's own tools
    let path = if tools {
        format!("{}:/usr/bin:/bin", stub.display())
    } else {
        format!("{}", stub.display())
    };
    let out = Command::new("/bin/bash")
        .arg("-c")
        .arg(format!(
            "set -euo pipefail\nlog() {{ echo \"$*\"; }}\n{body}\necho \"RESULT ok\"\n"
        ))
        .env("PATH", path)
        .env("NN_TEST_DIR", &dir)
        .output()
        .expect("bash runs");
    let calls: Vec<String> = fs::read_to_string(dir.join("calls"))
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect();
    let left = ["northnarrow-scan", "northnarrow-worker"]
        .iter()
        .filter(|u| dir.join(format!("user.{u}")).exists())
        .map(|u| u.to_string())
        .collect();
    (
        Run {
            status: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
            calls,
        },
        left,
    )
}

/// The account lines of install.sh after the block: its two calls.
fn install_accounts_body() -> String {
    let text = read("deploy/install.sh");
    let block = block("deploy/install.sh", "system_users");
    let after = &text[text.find("# <<< system_users").unwrap() + "# <<< system_users".len()..];
    let calls: String = after
        .lines()
        .skip(1)
        .take_while(|l| l.starts_with("ensure_system_user") || l.starts_with("    \""))
        .collect::<Vec<_>>()
        .join("\n");
    format!("{}\n{block}\n{calls}", check_accounts_body())
}

/// Review of #480 (F11): install.sh's check of the accounts that already
/// exist, and its two calls.
fn check_accounts_body() -> String {
    let text = read("deploy/install.sh");
    let block = block("deploy/install.sh", "system_user_check");
    let after =
        &text[text.find("# <<< system_user_check").unwrap() + "# <<< system_user_check".len()..];
    let calls: String = after
        .lines()
        .skip(1)
        .take_while(|l| l.starts_with("check_system_user"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        calls,
        "check_system_user \"$SCAN_USER\"\ncheck_system_user \"$WORKER_USER\""
    );
    format!(
        "SCAN_USER=northnarrow-scan\nWORKER_USER=northnarrow-worker\n\
         LOGIN_DEFS=$NN_TEST_DIR/login.defs\nPROC_ROOT=$NN_TEST_DIR/proc\n{block}\n{calls}"
    )
}

/// Review of #480 (F11): an account of the agent's names that exists is
/// used as it is, so install.sh refuses one it would not have created —
/// root's ids, a login-range uid or gid, a login shell, a usable password
/// or none, another group — with a message that names what is wrong, and
/// before anything on the host changes; the account it creates passes,
/// and so does one without a shadow entry.
#[test]
fn install_refuses_an_existing_account_it_would_not_have_created() {
    let body = check_accounts_body();
    let ok = Account::default();
    let scan = Account {
        uid: "989",
        gid: "989",
        ..ok.clone()
    };
    let (r, _) = accounts_run_as(
        "accounts-check-ok",
        &body,
        &[
            ("northnarrow-scan", scan),
            ("northnarrow-worker", ok.clone()),
        ],
        true,
    );
    assert!(r.stdout.contains("RESULT ok"), "{r:#?}");
    let (r, _) = accounts_run_as(
        "accounts-check-false-no-shadow",
        &body,
        &[(
            "northnarrow-worker",
            Account {
                shell: "/bin/false",
                shadow: None,
                ..ok.clone()
            },
        )],
        true,
    );
    assert!(r.stdout.contains("RESULT ok"), "{r:#?}");
    // an upgrade: the running agent's worker runs as the account
    let (r, _) = accounts_run_procs(
        "accounts-check-agent-child",
        &body,
        &[("northnarrow-worker", ok.clone())],
        Some(4000),
        &[(4001, 990, 4000)],
    );
    assert!(r.stdout.contains("RESULT ok"), "{r:#?}");
    // another process as the account (no agent, or not its child), a uid
    // another account shares
    for (case, agent, procs, why) in [
        (
            "foreign-process",
            Some(4000),
            vec![(4001, 990, 4000), (4100, 990, 1)],
            "process 4100 runs as it and is not the agent's child",
        ),
        (
            "process-no-agent",
            None,
            vec![(4001, 990, 4000)],
            "process 4001 runs as it",
        ),
    ] {
        let (r, _) = accounts_run_procs(
            &format!("accounts-check-{case}"),
            &body,
            &[("northnarrow-worker", ok.clone())],
            agent,
            &procs,
        );
        assert_eq!(r.status, 1, "{case}: {r:#?}");
        assert!(r.stderr.contains(why), "{case}: {r:#?}");
    }
    let (r, _) = accounts_run_as(
        "accounts-check-shared-uid",
        &body,
        &[
            ("northnarrow-worker", ok.clone()),
            ("northnarrow-scan", ok.clone()),
        ],
        true,
    );
    assert_eq!(r.status, 1, "{r:#?}");
    assert!(
        r.stderr.contains("the existing account northnarrow-scan")
            && r.stderr.contains("uid 990 shared with northnarrow-worker"),
        "{r:#?}"
    );
    let bad: [(&str, Account, &str); 8] = [
        (
            "root-uid",
            Account {
                uid: "0",
                ..ok.clone()
            },
            "root's",
        ),
        (
            "root-gid",
            Account {
                gid: "0",
                ..ok.clone()
            },
            "root's",
        ),
        (
            "login-uid",
            Account {
                uid: "1001",
                ..ok.clone()
            },
            "not a system account",
        ),
        (
            "login-gid",
            Account {
                gid: "1001",
                groups: Some("1001"),
                ..ok.clone()
            },
            "not a system account",
        ),
        (
            "shell",
            Account {
                shell: "/bin/bash",
                ..ok.clone()
            },
            "its shell is '/bin/bash'",
        ),
        (
            "password",
            Account {
                shadow: Some("$6$salt$hash"),
                ..ok.clone()
            },
            "a usable password",
        ),
        (
            "empty-password",
            Account {
                shadow: Some(""),
                ..ok.clone()
            },
            "a usable password",
        ),
        (
            "groups",
            Account {
                groups: Some("990 27"),
                ..ok.clone()
            },
            "groups '990 27'",
        ),
    ];
    for (case, account, why) in bad {
        for who in ["northnarrow-worker", "northnarrow-scan"] {
            let (r, _) = accounts_run_as(
                &format!("accounts-check-{case}-{who}"),
                &body,
                &[(who, account.clone())],
                true,
            );
            assert_eq!(r.status, 1, "{case} {who}: {r:#?}");
            assert!(!r.stdout.contains("RESULT ok"), "{case} {who}: {r:#?}");
            assert!(
                r.stderr.contains(&format!(
                    "the existing account {who} is not the unprivileged"
                )) && r.stderr.contains(why)
                    && r.stderr.contains("Refused"),
                "{case} {who}: {r:#?}"
            );
            assert!(r.calls.is_empty(), "nothing changed: {r:#?}");
        }
    }
    // the check runs before anything on the host changes: in the
    // preflight, before the transaction and the stop of a running install
    let text = read("deploy/install.sh");
    let at = text.find("check_system_user \"$WORKER_USER\"").unwrap();
    assert!(
        at < text
            .find("# Lab PR 220: replacing an install is a transaction")
            .unwrap()
    );
    assert!(at < text.find("\nstop_nn_unit() {").unwrap());
    assert!(at > text.find("\nrequire_nft\n").unwrap());
}

/// R14a: install.sh creates the workers' account as it creates the
/// scanner's — a system user, its own group, no home, no shell — once, in a
/// full install and the packages' configure step alike (the block runs in
/// both); an account that exists is kept; without useradd it warns and the
/// install goes on.
#[test]
fn install_creates_the_worker_and_scanner_accounts() {
    let body = install_accounts_body();
    let (r, left) = accounts_run("accounts-new", &body, &[], true);
    assert!(r.stdout.contains("RESULT ok"), "{r:#?}");
    assert_eq!(left, ["northnarrow-scan", "northnarrow-worker"]);
    for u in ["northnarrow-scan", "northnarrow-worker"] {
        let call = r
            .calls
            .iter()
            .find(|c| c.ends_with(&format!(" {u}")))
            .unwrap_or_else(|| panic!("no useradd for {u}: {r:#?}"));
        for flag in [
            "--system",
            "--user-group",
            "--no-create-home",
            "--home-dir /nonexistent",
            "--shell",
        ] {
            assert!(call.contains(flag), "{u}: {flag} in {call}");
        }
        assert!(call.contains("nologin"), "{call}");
    }
    let (r, _) = accounts_run("accounts-kept", &body, &["northnarrow-worker"], true);
    assert!(r.stdout.contains("RESULT ok"), "{r:#?}");
    assert_eq!(r.calls.len(), 1, "only the missing one: {r:#?}");
    assert!(r.calls[0].ends_with(" northnarrow-scan"));
    let (r, left) = accounts_run("accounts-no-useradd", &body, &[], false);
    assert!(r.stdout.contains("RESULT ok"), "{r:#?}");
    assert!(left.is_empty());
    assert!(r.stderr.contains("no northnarrow-worker account"), "{r:#?}");
    // the block is reached in the configure mode too: after the full
    // mode's binary switch, before the units start
    let text = read("deploy/install.sh");
    let at = text.find("# >>> system_users").unwrap();
    assert!(
        text.find("if [[ $MODE == configure ]]; then\n    # Migration")
            .unwrap()
            < at
    );
    assert!(
        at < text
            .rfind("start_units \"${UNITS_TO_RESTART[@]}\"")
            .unwrap()
    );
}

/// R14a: uninstall.sh removes both accounts (their own groups with them),
/// and only the ones that exist.
#[test]
fn uninstall_removes_the_worker_and_scanner_accounts() {
    let body = block("deploy/uninstall.sh", "remove_users");
    let (r, left) = accounts_run(
        "accounts-removed",
        &body,
        &["northnarrow-scan", "northnarrow-worker"],
        true,
    );
    assert!(r.stdout.contains("RESULT ok"), "{r:#?}");
    assert!(left.is_empty(), "{left:?}");
    assert_eq!(
        r.calls,
        ["userdel northnarrow-scan", "userdel northnarrow-worker"]
    );
    let (r, _) = accounts_run("accounts-one-left", &body, &["northnarrow-worker"], true);
    assert_eq!(r.calls, ["userdel northnarrow-worker"]);
}

/// The text of shell function `name` in `rel`: from `name() {` to the first
/// line that is `}`.
fn shell_fn(rel: &str, name: &str) -> String {
    let text = read(rel);
    let start = text
        .find(&format!("\n{name}() {{"))
        .unwrap_or_else(|| panic!("{rel}: no {name}()"))
        + 1;
    let end = text[start..]
        .find("\n}\n")
        .map(|i| start + i + 3)
        .unwrap_or_else(|| panic!("{rel}: {name}() not closed"));
    text[start..end].to_string()
}

/// Lot 277 (the re-review of #494, R2): the start-in-cgroup tracker's
/// programs, pinned beside the pin root, outlive an upgrade on purpose —
/// `install.sh --upgrade` does not wait for the ids the agent lists as
/// `kept`, and `uninstall.sh` waits for every id and removes the tracker's
/// pin directories with the root.
#[test]
fn an_upgrade_keeps_the_tracker_and_an_uninstall_removes_it() {
    let dir = case_dir("tracker-kept");
    let ids = dir.join("own-ids");
    fs::write(
        &ids,
        "# northnarrow-agent pid 7: loaded BPF programs (id name [kept])\n\
         12 task_kill\n40 cgroup_join_mark kept\n41 cgroup_join_src kept\n9 file_open\n",
    )
    .unwrap();
    let run = |rel: &str, body: &str| {
        let out = Command::new("bash")
            .arg("-c")
            .arg(format!("set -euo pipefail\n{body}"))
            .env("OWN_IDS_FILE", &ids)
            .env("BPFFS_ROOT", dir.join("pins"))
            .output()
            .expect("bash runs");
        assert!(
            out.status.success(),
            "{rel}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    let install = shell_fn("deploy/install.sh", "read_own_prog_ids");
    assert_eq!(
        run("install.sh", &format!("{install}\nread_own_prog_ids")),
        "9 12",
        "the upgrade waits for the pin root's programs only"
    );
    let uninstall = shell_fn("deploy/uninstall.sh", "read_own_prog_ids");
    assert_eq!(
        run("uninstall.sh", &format!("{uninstall}\nread_own_prog_ids")),
        "9 12 40 41",
        "the uninstall waits for every program"
    );
    // the uninstall's removal: the root and every tracker directory beside it
    for d in [
        "pins",
        "pins-cgroup-join-v1-64",
        "pins-cgroup-join-v2-262144",
    ] {
        fs::create_dir_all(dir.join(d)).unwrap();
        fs::write(dir.join(d).join("link_x"), "").unwrap();
    }
    fs::create_dir_all(dir.join("pins-other")).unwrap();
    let fns = ["tracker_pin_dirs", "pins_present", "remove_pins"]
        .map(|f| shell_fn("deploy/uninstall.sh", f))
        .join("\n");
    let listed = run("uninstall.sh", &format!("{fns}\ntracker_pin_dirs"));
    assert_eq!(
        listed.lines().collect::<Vec<_>>(),
        [
            dir.join("pins-cgroup-join-v1-64").display().to_string(),
            dir.join("pins-cgroup-join-v2-262144").display().to_string(),
        ],
        "the tracker's directories, beside the root"
    );
    // with the root already gone, the tracker's directories alone are pins
    fs::rename(dir.join("pins"), dir.join("pins-moved-away")).unwrap();
    assert_eq!(
        run(
            "uninstall.sh",
            &format!("{fns}\npins_present && echo present")
        ),
        "present"
    );
    fs::rename(dir.join("pins-moved-away"), dir.join("pins")).unwrap();
    assert_eq!(
        run(
            "uninstall.sh",
            &format!("{fns}\npins_present && echo present\nremove_pins\npins_present || echo gone")
        ),
        "present\ngone"
    );
    for d in [
        "pins",
        "pins-cgroup-join-v1-64",
        "pins-cgroup-join-v2-262144",
    ] {
        assert!(!dir.join(d).exists(), "{d} left by the uninstall");
    }
    assert!(
        dir.join("pins-other").exists(),
        "only the tracker's directories"
    );
    // install.sh's purge of the root leaves the tracker's directory
    fs::create_dir_all(dir.join("pins/x")).unwrap();
    fs::create_dir_all(dir.join("pins-cgroup-join-v1-64")).unwrap();
    let purge = shell_fn("deploy/install.sh", "purge_pin_root");
    run("install.sh", &format!("{purge}\npurge_pin_root"));
    assert!(!dir.join("pins").exists());
    assert!(
        dir.join("pins-cgroup-join-v1-64").exists(),
        "the upgrade keeps the tracker's pins"
    );
}
