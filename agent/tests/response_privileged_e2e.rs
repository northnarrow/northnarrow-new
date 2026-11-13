//! External audit NN-AUD-234 — privileged e2e of WHO the response hits.
//!
//! The detection suites run `--detect-only` (D7) or assert the verdict
//! only; nothing checked that an enforced kill lands on the offender and
//! on nothing else. This suite runs a real agent WITHOUT `--detect-only`
//! and asserts, on the signed detection record and on the processes
//! themselves:
//!
//! - the record names the offender (`principal.pid`, `exe`);
//! - its `response` is the bare action name — the action was carried out
//!   (a kill that found the process gone, was refused or failed now
//!   names its outcome, see `detection_store::describe_response`);
//! - the offender died by SIGKILL;
//! - a decoy sibling with the same name and parent, and the test harness
//!   (the offender's parent), run on;
//! - a child the offender forked dies with it (lab PR 166: the kill of an
//!   exec from `/tmp` takes the tree, descendants only).
//!
//! Not covered here: a process spared by the host-critical guard and
//! recorded as refused. Making a test process count as the watchdog or
//! the SSH service on the lab guest means rewriting the agent's watchdog
//! pidfile identity or moving a process into `ssh.service`, both of which
//! change protected state; the composition (guard → executor → record)
//! is a unit test, `recorded_response_matches_what_the_executor_did` in
//! `agent/src/detection_store.rs`.
//!
//! Requirements: root + bpf LSM + bpffs; `/tmp` mounted exec (as the D7
//! suite needs); no production agent holding the pin tree.
//!
//! Run:
//!   sudo -E env "PATH=$PATH" cargo test --release \
//!     -p northnarrow-agent --test response_privileged_e2e \
//!     --features "test-privileged debug-trigger" \
//!     -- --include-ignored --test-threads=1

#![cfg(feature = "test-privileged")]

// The re-review of #475: the dropper test stands the decision thread still
// (`debug-stall-loop`) — a privileged build without `debug-trigger` would
// drop it silently; the lab, the gates and CI build both.
#[cfg(not(feature = "debug-trigger"))]
compile_error!(
    "response_privileged_e2e needs `debug-trigger` with `test-privileged` (the /tmp dropper \
     test stands the decision thread still)"
);

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::agent_state::{AgentState, InstalledAgent, Launch};
use common::EniIptablesGuard;

const SOCKET_POLL_TIMEOUT: Duration = Duration::from_secs(15);
const RECORD_POLL_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const BPFFS_PIN_ROOT: &str = "/sys/fs/bpf/northnarrow";

fn nn_admin_bin() -> &'static str {
    env!("CARGO_BIN_EXE_nn-admin")
}
fn configs() -> PathBuf {
    PathBuf::from(env!("NN_REPO_ROOT")).join("configs")
}

fn wipe_pin_tree() {
    let pin = Path::new(BPFFS_PIN_ROOT);
    if let Ok(entries) = std::fs::read_dir(pin) {
        for e in entries.flatten() {
            let _ = std::fs::remove_file(e.path());
        }
    }
    let _ = std::fs::remove_dir(pin);
}

/// A child of the test, killed and reaped on drop if still running.
struct Spawned(Child);
impl Drop for Spawned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// SIGQUIT-on-drop (the LSM hook denies SIGKILL and SIGTERM).
struct AgentGuard(Option<Child>);
impl Drop for AgentGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            common::quit_agent(&mut c);
        }
    }
}

/// Lot 278: the host's per-rule policy and its `.sig` as a test found
/// them (dev, inode, size, mtime; `None` absent), compared again once the
/// agent quit — a fixture's policy goes in its own directory, and one
/// stored on the host stayed there for the next suites (the guest run of
/// 7a731dab).
struct HostPolicyUnchanged(Vec<(PathBuf, Option<FileStamp>)>);
/// dev, inode, size, mtime (s, ns).
type FileStamp = (u64, u64, u64, i64, i64);
impl HostPolicyUnchanged {
    fn snapshot() -> Self {
        Self(Self::stamps())
    }

    /// The stamps alone: a second `HostPolicyUnchanged` built in `drop`
    /// would be dropped, and so compared, again (the guest run of
    /// cb125646: a stack overflow).
    fn stamps() -> Vec<(PathBuf, Option<FileStamp>)> {
        use std::os::unix::fs::MetadataExt;
        let file = PathBuf::from(northnarrow_agent::decision::rule_policy::DEFAULT_LOCAL);
        let sig = northnarrow_agent::config::overlay_auth::sig_path(&file);
        [file, sig]
            .into_iter()
            .map(|p| {
                let m = std::fs::symlink_metadata(&p)
                    .ok()
                    .map(|m| (m.dev(), m.ino(), m.len(), m.mtime(), m.mtime_nsec()));
                (p, m)
            })
            .collect()
    }
}
impl Drop for HostPolicyUnchanged {
    fn drop(&mut self) {
        let now = Self::stamps();
        if now != self.0 {
            common::fail_teardown(&format!(
                "the host's per-rule policy changed during the test (a fixture writes in its own \
                 directory): before {:?}, after {:?}",
                self.0, now
            ));
        }
    }
}

/// An enforcing agent with every state file in a per-test tempdir, empty
/// allow/blocklists, no FIM watch.
struct Fixture {
    agent_log: PathBuf,
    detections_log: PathBuf,
    _agent_guard: AgentGuard,
    /// Lab PR 256: the agent runs from a root-owned copy, as in the other
    /// suites (it ran from `target/`); removed after it stopped.
    _installed_agent: InstalledAgent,
    /// Lab PR 269: its admin socket (the debug triggers sit next to it).
    #[cfg_attr(not(feature = "debug-trigger"), allow(dead_code))]
    admin_socket: PathBuf,
    /// Lot 278: checked once the agent quit (dropped after its guard).
    _host_policy: HostPolicyUnchanged,
    /// Lot 278: dropped last, once the agent quit — a policy it stored
    /// there is a protected inode while it runs.
    _tempdir: tempfile::TempDir,
}

impl Fixture {
    fn setup() -> Self {
        Self::setup_with(None)
    }

    /// Lot 278: with `policy`, a signed per-rule policy set through the
    /// admin socket once the agent runs (`nn-admin policy set`, a key with
    /// `config-manage`, nn-admin from a root-owned copy).
    fn setup_with(policy: Option<&str>) -> Self {
        Self::setup_opts(policy, None)
    }

    /// Lot 322: with `exec_policy`, the exec policy in enforce mode with
    /// that table (`--exec-policy-local`, in the test's directory; the
    /// unsigned overlays are allowed here).
    fn setup_opts(policy: Option<&str>, exec_policy: Option<&str>) -> Self {
        let host_policy = HostPolicyUnchanged::snapshot();
        wipe_pin_tree();
        let tempdir = tempfile::tempdir().expect("tempdir");
        let dir = tempdir.path().to_path_buf();
        let state = AgentState::new(&dir);
        let installed_agent = InstalledAgent::install();

        // Before the agent runs: nn-admin is not exec'd again afterwards.
        let status = Command::new(nn_admin_bin())
            .arg("init")
            .arg("--priv-out")
            .arg(dir.join("admin.priv"))
            .arg("--pub-append")
            .arg(state.admin_pub())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .expect("spawn nn-admin init");
        assert!(status.success(), "nn-admin init failed");
        // lot 278: a second key holding `config-manage`, for the policy
        let policy_key = dir.join("policy.priv");
        if policy.is_some() {
            let pub_tmp = dir.join("policy.pub");
            let status = Command::new(nn_admin_bin())
                .arg("init")
                .arg("--priv-out")
                .arg(&policy_key)
                .arg("--pub-append")
                .arg(&pub_tmp)
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .status()
                .expect("spawn nn-admin init (policy key)");
            assert!(status.success(), "nn-admin init (policy key) failed");
            let hex = std::fs::read_to_string(&pub_tmp)
                .expect("read the policy key's pub")
                .lines()
                .find(|l| !l.starts_with('#') && !l.trim().is_empty())
                .expect("a pub line")
                .trim()
                .to_string();
            let mut admin_pub = std::fs::read_to_string(state.admin_pub()).expect("admin.pub");
            admin_pub.push_str(&format!("{hex} config-manage\n"));
            std::fs::write(state.admin_pub(), admin_pub).expect("write admin.pub");
        }

        let combat = dir.join("combat-rules.v4");
        std::fs::copy(configs().join("combat-rules.v4"), &combat).expect("copy combat rules");
        let templates = dir.join("canary-templates");
        std::fs::create_dir(&templates).expect("mkdir canary-templates");
        for entry in std::fs::read_dir(configs().join("canary-templates")).expect("templates") {
            let path = entry.expect("template dirent").path();
            if path.extension().and_then(|e| e.to_str()) == Some("tmpl") {
                let base = path.file_name().expect("template basename");
                std::fs::copy(&path, templates.join(base)).expect("copy template");
            }
        }
        let empty = |name: &str| {
            let p = dir.join(name);
            std::fs::write(&p, "").unwrap_or_else(|_| panic!("write {name}"));
            p
        };

        let rule_policy = dir.join("rule-policy.local");
        let agent_log = dir.join("agent.log");
        let detections_log = state.detections();
        let log = std::fs::File::create(&agent_log).expect("create agent.log");
        let log_err = log.try_clone().expect("clone agent.log");
        let mut env = vec![common::OWN_DEFAULT_LISTS_ENV];
        let exec_policy_local = dir.join("exec-policy.local");
        if let Some(table) = exec_policy {
            std::fs::write(&exec_policy_local, table).expect("write the exec policy");
            env.push(("NN_EXEC_POLICY", "enforce"));
        }
        let mut cmd = installed_agent.command(&state, Launch::Direct, &env);
        if exec_policy.is_some() {
            cmd.arg("--exec-policy-local").arg(&exec_policy_local);
        }
        cmd.arg("--combat-rules")
            .arg(&combat)
            .arg("--fim-paths-v1")
            .arg(empty("fim-paths.v1"))
            .arg("--fim-paths-local")
            .arg(empty("fim-paths.local"))
            .arg("--canary-template-dir")
            .arg(&templates)
            // Lot 278: the per-rule policy in the test's directory (absent
            // unless `policy` is set): the host's
            // /etc/northnarrow/rule-policy.local is neither loaded (the
            // unsigned overlays are allowed here) nor written by the
            // `policy set` below.
            .arg("--rule-policy-local")
            .arg(&rule_policy);
        for (flag, file) in [
            ("--netflow-blocklist-v1", "netflow-blocklist.v1"),
            ("--netflow-blocklist-local", "netflow-blocklist.local"),
            ("--netflow-ja3-blocklist-v1", "netflow-ja3-blocklist.v1"),
            (
                "--netflow-ja3-blocklist-local",
                "netflow-ja3-blocklist.local",
            ),
            ("--process-comm-allowlist-v1", "process-comm-allowlist.v1"),
            (
                "--process-comm-allowlist-local",
                "process-comm-allowlist.local",
            ),
            ("--netflow-comm-allowlist-v1", "netflow-comm-allowlist.v1"),
            (
                "--netflow-comm-allowlist-local",
                "netflow-comm-allowlist.local",
            ),
        ] {
            cmd.arg(flag).arg(empty(file));
        }
        // Responses enforced: no `--detect-only`.
        let child = cmd
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()
            .expect("spawn northnarrow-agent for the response e2e");
        let guard = AgentGuard(Some(child));

        let socket = state.admin_socket();
        let deadline = Instant::now() + SOCKET_POLL_TIMEOUT;
        while !socket.exists() {
            assert!(
                Instant::now() < deadline,
                "agent never opened its admin socket; agent.log tail:\n{}",
                tail(&agent_log)
            );
            std::thread::sleep(POLL_INTERVAL);
        }

        if let Some(policy) = policy {
            let file = dir.join("rule-policy.candidate");
            std::fs::write(&file, policy).expect("write the policy");
            // a root-owned copy: no root exec from the build tree
            let admin = common::install_to_priv_bin(Path::new(nn_admin_bin()));
            let out = Command::new(&admin.path)
                .args(["policy", "set", "--file"])
                .arg(&file)
                .arg("--key")
                .arg(&policy_key)
                .arg("--agent-id-file")
                .arg(state.agent_id_file())
                .arg("--socket")
                .arg(&socket)
                .stdin(Stdio::null())
                .output()
                .expect("spawn nn-admin policy set");
            assert!(
                out.status.success(),
                "nn-admin policy set failed: {}{}\nagent.log tail:\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
                tail(&agent_log)
            );
            assert_eq!(
                std::fs::read_to_string(&rule_policy).ok().as_deref(),
                Some(policy),
                "the policy is stored in the test's directory, not the host's"
            );
        }

        Self {
            _tempdir: tempdir,
            agent_log,
            detections_log,
            _agent_guard: guard,
            _installed_agent: installed_agent,
            admin_socket: socket,
            _host_policy: host_policy,
        }
    }

    /// Lab PR 269 (review of #475), `debug-trigger` builds: the decision
    /// thread stands still `secs` seconds — the trigger next to the admin
    /// socket, taken at the loop's next check, and a second for the thread
    /// to reach its stall — so what a test starts meanwhile is judged after.
    #[cfg(feature = "debug-trigger")]
    fn stall_decision(&self, secs: u64) {
        let trigger = self
            .admin_socket
            .parent()
            .expect("the socket's directory")
            .join("debug-stall-loop");
        std::fs::write(&trigger, secs.to_string()).expect("write the stall trigger");
        let taken = common::wait_until(Duration::from_secs(15), || {
            (!trigger.exists()).then_some(())
        });
        assert!(taken.is_some(), "the agent did not take the stall trigger");
        std::thread::sleep(Duration::from_secs(1));
    }

    /// The detection record of the process `pid`.
    fn wait_record_of(&self, pid: u32) -> serde_json::Value {
        let pid = u64::from(pid);
        common::wait_until(RECORD_POLL_TIMEOUT, || {
            common::read_jsonl_strict(&self.detections_log)
                .into_iter()
                .find(|r| r["principal"]["pid"].as_u64() == Some(pid))
        })
        .unwrap_or_else(|| {
            panic!(
                "no detection record of pid {pid} within {RECORD_POLL_TIMEOUT:?}; records: {:?}\n\
                 agent.log tail:\n{}",
                common::read_jsonl_strict(&self.detections_log),
                tail(&self.agent_log)
            )
        })
    }
}

fn tail(path: &Path) -> String {
    let log = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    lines[lines.len().saturating_sub(30)..].join("\n")
}

/// A copy of `/bin/sleep` in a fresh directory under `/tmp`, keeping the
/// name `sleep` (a multi-call coreutils dispatches on it).
fn tmp_sleep() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("nnresp")
        .tempdir_in("/tmp")
        .expect("tempdir under /tmp");
    // lot 278: run as `nobody` (R001's tree kill, in every posture)
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
        .expect("chmod the offender's directory");
    let bin = dir.path().join("sleep");
    std::fs::copy("/bin/sleep", &bin).expect("copy /bin/sleep");
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    (dir, bin)
}

/// (a) An exec from `/tmp` (R001, or the exec rule that matches it first;
/// since lab PR 166 a tree kill either way) by a child of the harness, run
/// as `nobody` (lot 278: root's exec from `/tmp` is R009's, killed in
/// COMBAT or under `enforce R009` — below). A
/// decoy with the same name and the same parent runs beside it. The
/// record names the offender and the bare action name (carried out); the
/// offender died by SIGKILL; the decoy and the harness run on.
///
/// Regressions it catches: a kill aimed at the parent kills the harness;
/// at the wrong process (by name), the decoy; a tree kill that reaches
/// past the offender's descendants, either; recorded but not landed, the
/// offender's exit; a refusal or a miss recorded as the action, the
/// `response` check.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn tmp_exec_kill_hits_the_offender_only() {
    let _eni = EniIptablesGuard::install();
    let fx = Fixture::setup();

    let mut decoy = Spawned(
        Command::new("sleep")
            .arg("120")
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn the decoy"),
    );
    let (_dir, bin) = tmp_sleep();
    let mut offender = Spawned({
        use std::os::unix::process::CommandExt;
        Command::new(&bin)
            .arg("120")
            .uid(NOBODY)
            .gid(NOBODY)
            .stdout(Stdio::null())
            .spawn()
            .expect("exec the /tmp offender")
    });
    let pid = offender.0.id();

    let rec = fx.wait_record_of(pid);
    assert_eq!(rec["exe"].as_str(), bin.to_str(), "record: {rec}");
    assert_eq!(
        rec["rule_id"].as_str(),
        Some("R001_ExecFromTmp"),
        "record: {rec}"
    );
    let action = rec["verdict"]["Rule"].as_str();
    assert_eq!(
        action,
        Some("KillProcessTree"),
        "a tree kill was expected (lab PR 166); record: {rec}"
    );
    assert_eq!(
        rec["response"].as_str(),
        action,
        "the bare action name: the kill was carried out; record: {rec}"
    );

    let status = common::wait_exit(&mut offender.0, RECORD_POLL_TIMEOUT)
        .unwrap_or_else(|| panic!("the offender still runs: the kill did not land; record: {rec}"));
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "the offender ended otherwise: {status:?}; record: {rec}"
    );
    assert!(
        decoy.0.try_wait().expect("decoy status").is_none(),
        "the decoy sibling was killed; record: {rec}"
    );
    // The decoy left no record: the response followed the event, not the name.
    let decoy_pid = u64::from(decoy.0.id());
    let decoy_records: Vec<_> = common::read_jsonl_strict(&fx.detections_log)
        .into_iter()
        .filter(|r| r["principal"]["pid"].as_u64() == Some(decoy_pid))
        .collect();
    assert!(decoy_records.is_empty(), "decoy records: {decoy_records:?}");
}

/// `nobody` on Debian and Ubuntu.
const NOBODY: u32 = 65534;

/// The lab's root dropper (lab PR 166), built with `cc` in a fresh
/// directory under `/tmp` that another user can enter: it forks at once;
/// the child writes its pid on stdout and sleeps, the parent waits in
/// `pause()`. The child never execs, so it draws no verdict of its own.
#[cfg(feature = "debug-trigger")]
fn tmp_fork_dropper() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("nnfork")
        .tempdir_in("/tmp")
        .expect("tempdir under /tmp");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
        .expect("chmod the dropper's directory");
    let src = dir.path().join("dropper.c");
    std::fs::write(
        &src,
        r#"
#include <stdio.h>
#include <unistd.h>
int main(void) {
    if (fork() == 0) {
        printf("%d\n", (int)getpid());
        fflush(stdout);
        sleep(30);
        return 0;
    }
    pause();
    return 0;
}
"#,
    )
    .expect("write the dropper source");
    let bin = dir.path().join("dropper");
    let status = Command::new("cc")
        .arg("-O0")
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .expect("spawn cc to build the dropper");
    assert!(status.success(), "cc failed to build the dropper");
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    (dir, bin)
}

/// (b) Lab PR 166: a dropper from `/tmp` that forked before the verdict.
/// As `nobody` (R001): the record names the dropper and `KillProcessTree`,
/// carried out; the dropper died by SIGKILL; its child is gone too, and the
/// harness, their parent, runs on. As root (R009), lot 278: in OBSERVING
/// (the agent the test starts) the record is R009's High, the kill held —
/// R009 kills in COMBAT only, or under a signed `enforce` — and the
/// dropper and its child run on.
///
/// Regression it catches: a single-process kill of the exec — the child
/// ran on under init with the image from `/tmp` (seen in the lab with
/// R009, which runs ahead of R001); and a root exec from `/tmp` killed in
/// OBSERVING (the installer run from an unpacked tree, lot 278).
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
#[cfg(feature = "debug-trigger")]
fn tmp_dropper_forked_child_dies_with_it() {
    let _eni = EniIptablesGuard::install();
    // Built before the agent runs: nothing here should draw a verdict.
    let (_dir, bin) = tmp_fork_dropper();
    let fx = Fixture::setup();

    for (uid, rule, killed) in [
        (None, "R009_RootExecFromUserPath", false),
        (Some(NOBODY), "R001_ExecFromTmp", true),
    ] {
        dropper_case(&fx, &bin, uid, rule, killed);
    }
}

/// Lot 278: under a signed `enforce R009` (the operator's choice) a root
/// dropper from `/tmp` dies with its forked child in every posture — the
/// kill of the tree, R009's, as before the decision of 03/11/2026.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
#[cfg(feature = "debug-trigger")]
fn root_tmp_dropper_under_enforce_r009_dies_with_its_child() {
    let _eni = EniIptablesGuard::install();
    let (_dir, bin) = tmp_fork_dropper();
    let fx = Fixture::setup_with(Some("enforce R009\n"));
    dropper_case(&fx, &bin, None, "R009_RootExecFromUserPath", true);
}

/// One run of the dropper (`uid`: `None` for root) under `fx`: its record
/// is `rule`'s, and its tree is killed (`killed`) or recorded with the kill
/// held and left running (then the test ends it).
#[cfg(feature = "debug-trigger")]
fn dropper_case(fx: &Fixture, bin: &Path, uid: Option<u32>, rule: &str, killed: bool) {
    use std::io::{BufRead, BufReader};
    use std::os::unix::process::CommandExt;
    let bin = bin.to_path_buf();
    let held = !killed;
    // Lab PR 269 (review of #475): the decision thread stands still
    // while the dropper starts, so its child exists — it has written its
    // pid — before the verdict, every run (with the decision on a thread
    // of its own the kill could land before the fork on ubuntu2204).
    fx.stall_decision(4);
    let mut cmd = Command::new(&bin);
    cmd.stdout(Stdio::piped());
    if let Some(id) = uid {
        cmd.uid(id).gid(id);
    }
    let mut dropper = Spawned(cmd.spawn().expect("exec the /tmp dropper"));
    let pid = dropper.0.id();
    let mut line = String::new();
    BufReader::new(dropper.0.stdout.take().expect("dropper stdout"))
        .read_line(&mut line)
        .expect("read the child's pid");
    let child: u32 = line.trim().parse().unwrap_or_else(|_| {
        panic!("uid {uid:?}: no child pid ({line:?}) though the verdict was held back")
    });
    assert!(
        !common::pid_gone(child) && runs_image(child, &bin),
        "uid {uid:?}: the child {child} runs the dropper's image before the verdict"
    );

    let rec = fx.wait_record_of(pid);
    assert_eq!(
        rec["rule_id"].as_str(),
        Some(rule),
        "uid {uid:?}; record: {rec}"
    );
    assert_eq!(rec["exe"].as_str(), bin.to_str(), "record: {rec}");
    if held {
        // lot 278: detected, High, the kill held in OBSERVING
        assert_eq!(
            rec["verdict"],
            serde_json::json!({"Rule": "Log"}),
            "record: {rec}"
        );
        assert_eq!(rec["severity"], "High", "record: {rec}");
        // judged below COMBAT (the exec from /tmp raised ENGAGED)
        assert_ne!(rec["posture_at"], "Combat", "record: {rec}");
        assert_eq!(rec["response"], "none", "record: {rec}");
        std::thread::sleep(Duration::from_secs(2));
        assert!(
            !common::pid_gone(pid) && !common::pid_gone(child),
            "the root dropper or its child was killed below COMBAT; record: {rec}"
        );
        // SAFETY: plain kill(2) of the child this test's dropper forked.
        unsafe { libc::kill(child as i32, libc::SIGKILL) };
        drop(dropper);
        let gone = common::wait_until(Duration::from_secs(5), || {
            processes_of(&bin).is_empty().then_some(())
        });
        assert!(
            gone.is_some(),
            "the root dropper's processes: {:?}",
            processes_of(&bin)
        );
        return;
    }
    assert_eq!(
        rec["verdict"],
        serde_json::json!({"Rule": "KillProcessTree"}),
        "uid {uid:?}; record: {rec}"
    );
    assert_eq!(
        rec["response"], "KillProcessTree",
        "the bare action name: the whole tree was killed; uid {uid:?}; record: {rec}"
    );
    let status = common::wait_exit(&mut dropper.0, RECORD_POLL_TIMEOUT).unwrap_or_else(|| {
        panic!("uid {uid:?}: the dropper still runs: the kill did not land; record: {rec}")
    });
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "uid {uid:?}: the dropper ended otherwise: {status:?}; record: {rec}"
    );
    let child_gone = common::wait_until(Duration::from_secs(5), || {
        common::pid_gone(child).then_some(())
    });
    assert!(
        child_gone.is_some(),
        "uid {uid:?}: the dropper's child {child} survived the kill; record: {rec}"
    );
    // No process runs the image from /tmp any more, deleted or not: the
    // child and any other descendant.
    let none_left = common::wait_until(Duration::from_secs(5), || {
        processes_of(&bin).is_empty().then_some(())
    });
    assert!(
        none_left.is_some(),
        "uid {uid:?}: processes of the dropper's image survived the kill: {:?} (child \
         {child}); record: {rec}",
        processes_of(&bin)
    );
}

/// `/proc/<pid>/exe` is `image`, or `image` deleted since (` (deleted)`).
#[cfg(feature = "debug-trigger")]
fn runs_image(pid: u32, image: &std::path::Path) -> bool {
    std::fs::read_link(format!("/proc/{pid}/exe")).is_ok_and(|exe| {
        exe == image || exe.as_os_str() == format!("{} (deleted)", image.display()).as_str()
    })
}

/// The pids whose executable is `image`, deleted or not (`/proc/<pid>/exe`;
/// read as root).
#[cfg(feature = "debug-trigger")]
fn processes_of(image: &std::path::Path) -> Vec<u32> {
    let mut pids = Vec::new();
    for entry in std::fs::read_dir("/proc").expect("read /proc").flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if runs_image(pid, image) {
            pids.push(pid);
        }
    }
    pids
}

// ── Lot 322: a staging preload refused at every exec, on every CPU ────

/// A shared object whose constructor writes the file named by
/// `NN_E2E_PRELOAD_MARK`: it ran, so the preload was not refused.
fn compile_marker_preload(dir: &Path) -> PathBuf {
    let src = dir.join("mark.c");
    std::fs::write(
        &src,
        "#include <fcntl.h>\n#include <stdlib.h>\n#include <unistd.h>\n\
         __attribute__((constructor)) static void m(void) {\n\
           const char *p = getenv(\"NN_E2E_PRELOAD_MARK\");\n\
           if (p) { int fd = open(p, O_WRONLY | O_CREAT, 0666); if (fd >= 0) close(fd); }\n\
         }\n",
    )
    .expect("write mark.c");
    let lib = dir.join("libmark.so");
    let st = Command::new("cc")
        .args(["-shared", "-fPIC", "-O2", "-o"])
        .arg(&lib)
        .arg(&src)
        .status()
        .expect("spawn cc");
    assert!(st.success(), "cc failed");
    std::fs::set_permissions(&lib, std::fs::Permissions::from_mode(0o755)).expect("chmod lib");
    lib
}

/// Lot 322 (the review of #546, F1): a 64-bit program that execs
/// `/usr/bin/true` through the 32-bit entry (`int $0x80`, eax 11) or the
/// x32 one (`0x40000000 | 520`), with `LD_PRELOAD=<lib>` and the marker in
/// an `envp` of 32-bit pointers below 4 GiB. Exit 77: refused (`EACCES`);
/// 38: the call does not exist on this kernel (x32 off); 1: another error.
fn compile_compat_exec(dir: &Path) -> PathBuf {
    let src = dir.join("compat_exec.c");
    std::fs::write(
        &src,
        r#"#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc < 4) return 2;
  char *low = mmap(NULL, 1 << 16, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
  if (low == MAP_FAILED) return 3;
  char *p = low + 1024;
  char *path = p; strcpy(p, "/usr/bin/true"); p += strlen(p) + 1;
  char *a0 = p; strcpy(p, "true"); p += strlen(p) + 1;
  char *e0 = p; p += sprintf(p, "LD_PRELOAD=%s", argv[2]) + 1;
  char *e1 = p; p += sprintf(p, "NN_E2E_PRELOAD_MARK=%s", argv[3]) + 1;
  uint32_t *av = (uint32_t *)low; av[0] = (uint32_t)(uintptr_t)a0; av[1] = 0;
  uint32_t *ev = (uint32_t *)(low + 64);
  ev[0] = (uint32_t)(uintptr_t)e0; ev[1] = (uint32_t)(uintptr_t)e1; ev[2] = 0;
  long ret;
  if (!strcmp(argv[1], "x32hi")) {
    /* lot 325 (R1): the real array above 4 GiB, a clean decoy at its low
       half; the kernel's x32 stub reads the register whole */
    unsigned long lo_a = 0x10000000UL, hi_a = lo_a | (1UL << 32);
    char *dlo = mmap((void *)lo_a, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    char *dhi = mmap((void *)hi_a, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (dlo != (char *)lo_a || dhi != (char *)hi_a) return 3;
    char *d0 = p; strcpy(p, "DECOY=clean"); p += strlen(p) + 1;
    uint32_t *decoy = (uint32_t *)dlo; decoy[0] = (uint32_t)(uintptr_t)d0; decoy[1] = 0;
    uint32_t *real = (uint32_t *)dhi;
    real[0] = (uint32_t)(uintptr_t)e0; real[1] = (uint32_t)(uintptr_t)e1; real[2] = 0;
    ret = syscall(0x40000000L | 520, path, av, (void *)hi_a);
    if (ret < 0) ret = -(long)errno;
  } else if (!strcmp(argv[1], "ia32")) {
    __asm__ volatile("int $0x80" : "=a"(ret)
                     : "a"(11), "b"((uint32_t)(uintptr_t)path),
                       "c"((uint32_t)(uintptr_t)av), "d"((uint32_t)(uintptr_t)ev)
                     : "memory");
  } else {
    ret = syscall(0x40000000L | 520, path, av, ev);
    if (ret < 0) ret = -(long)errno;
  }
  if (ret == -13) return 77;
  if (ret == -38) return 38;
  return 1;
}
"#,
    )
    .expect("write compat_exec.c");
    let bin = dir.join("compat_exec");
    let st = Command::new("cc")
        .args(["-O2", "-o"])
        .arg(&bin)
        .arg(&src)
        .status()
        .expect("spawn cc");
    assert!(st.success(), "cc failed");
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    bin
}

/// Lot 322: the exec environment's check refused 0 of 11 staging preloads
/// on Ubuntu 26.04's 7.0 — its programs sat on the `sys_enter_execve{,at}`
/// tracepoints, which ran there only for the execs entered on CPU 0 (20 of
/// 20 refused pinned to CPU 0, 6 of 20 unpinned, 2 of 10 from a service).
/// With a table that denies a staging preload in every tier, `N` execs of
/// `/usr/bin/true` with `LD_PRELOAD` from this test's directory under
/// `/tmp`, from unpinned threads while every CPU is busy (so the execs land
/// on every CPU), as root, as `nobody` and from a service (`systemd-run`):
/// every one is refused at exec (`EACCES`; a service's exec fails) and the
/// preload's constructor never runs. The same exec without the preload
/// runs. Fails on a kernel where the check runs on one CPU only.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn a_staging_preload_is_refused_at_every_exec_on_every_cpu() {
    use std::os::unix::process::CommandExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    const N: usize = 24;

    let _eni = EniIptablesGuard::install();
    let fx = Fixture::setup_opts(None, Some("preload * deny\n"));
    let armed = common::wait_until(Duration::from_secs(30), || {
        std::fs::read_to_string(&fx.agent_log).ok().and_then(|l| {
            l.lines()
                .find(|l| l.contains("exec policy armed in the kernel") && l.contains("env=true"))
                .map(str::to_string)
        })
    });
    let armed = armed.unwrap_or_else(|| {
        panic!(
            "the exec policy did not arm with the environment check; agent.log tail:\n{}",
            tail(&fx.agent_log)
        )
    });
    assert!(armed.contains("enforce"), "{armed}");

    let work = tempfile::Builder::new()
        .prefix("nn-e2e-322-")
        .tempdir_in("/tmp")
        .expect("tempdir under /tmp");
    std::fs::set_permissions(work.path(), std::fs::Permissions::from_mode(0o777))
        .expect("chmod the work directory");
    let lib = compile_marker_preload(work.path());
    let mark = |who: &str, i: usize| work.path().join(format!("mark.{who}.{i}"));

    // the controls (the review of #546, F8): the same exec without the
    // preload runs as root, as `nobody` and from a service, so a refusal
    // below is the preload's
    let st = Command::new("/usr/bin/true").status().expect("spawn true");
    assert!(st.success(), "/usr/bin/true without a preload: {st}");
    let st = Command::new("/usr/bin/true")
        .uid(65534)
        .gid(65534)
        .status()
        .expect("spawn true as nobody");
    assert!(
        st.success(),
        "/usr/bin/true as nobody without a preload: {st}"
    );
    let out = Command::new("systemd-run")
        .args([
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            "-p",
            "User=root",
            "/usr/bin/true",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("spawn systemd-run");
    assert!(
        out.status.success(),
        "a service's /usr/bin/true without a preload: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // every CPU busy for the run: the execs are spread by the scheduler
    let cpus = std::thread::available_parallelism()
        .map_or(2, |n| n.get())
        .min(16);
    let stop = Arc::new(AtomicBool::new(false));
    let spinners: Vec<_> = (0..cpus)
        .map(|_| {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut x = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    x = std::hint::black_box(x.wrapping_add(1));
                }
            })
        })
        .collect();

    // as root and as nobody, from unpinned threads
    // every exec not refused, once, with what showed it
    let mut ran: std::collections::BTreeMap<(&str, usize), Vec<String>> =
        std::collections::BTreeMap::new();
    for (who, uid) in [("root", None), ("nobody", Some(65534u32))] {
        let per = N.div_ceil(cpus);
        let outcomes: Vec<(usize, Result<(), String>)> = std::thread::scope(|sc| {
            let hs: Vec<_> = (0..cpus)
                .map(|t| {
                    let lib = &lib;
                    let mark = &mark;
                    sc.spawn(move || {
                        let mut out = Vec::new();
                        for k in 0..per {
                            let i = t * per + k;
                            if i >= N {
                                break;
                            }
                            let mut c = Command::new("/usr/bin/true");
                            c.env("LD_PRELOAD", lib)
                                .env("NN_E2E_PRELOAD_MARK", mark(who, i))
                                .stdout(Stdio::null())
                                .stderr(Stdio::null());
                            if let Some(u) = uid {
                                c.uid(u).gid(u);
                            }
                            let r = match c.spawn() {
                                Err(e) if e.raw_os_error() == Some(13) => Ok(()),
                                Err(e) => Err(format!("spawn failed otherwise: {e}")),
                                Ok(mut child) => {
                                    let st = child.wait();
                                    Err(format!("the exec ran ({st:?})"))
                                }
                            };
                            out.push((i, r));
                        }
                        out
                    })
                })
                .collect();
            hs.into_iter()
                .flat_map(|h| h.join().expect("exec thread"))
                .collect()
        });
        assert_eq!(outcomes.len(), N, "{who}");
        for (i, r) in outcomes {
            if let Err(e) = r {
                ran.entry((who, i)).or_default().push(e);
            }
            if mark(who, i).exists() {
                ran.entry((who, i))
                    .or_default()
                    .push("the preload ran".into());
            }
        }
    }

    // the review of #546 (F1): through the 32-bit entry and the x32 one,
    // envp an array of 32-bit pointers (x32 only where the kernel has it)
    let compat = compile_compat_exec(work.path());
    let mut x32_absent = 0;
    for i in 0..N / 3 {
        // lot 325 (R1): x32's envp the register whole (`x32hi`)
        for abi in ["ia32", "x32", "x32hi"] {
            let who = abi;
            let st = Command::new(&compat)
                .arg(abi)
                .arg(&lib)
                .arg(mark(who, i))
                .stdin(Stdio::null())
                .status()
                .expect("spawn compat_exec");
            match st.code() {
                Some(77) => {}
                Some(38) if abi.starts_with("x32") => x32_absent += 1,
                other => {
                    ran.entry((who, i))
                        .or_default()
                        .push(format!("not refused ({other:?})"));
                }
            }
            if mark(who, i).exists() {
                ran.entry((who, i))
                    .or_default()
                    .push("the preload ran".into());
            }
        }
    }
    eprintln!(
        "compat execs: ia32 {} refused; x32 (both shapes) absent on this kernel in {x32_absent} \
         of {}",
        N / 3,
        2 * (N / 3)
    );

    // from a service: the unit's exec fails, the preload never runs
    for i in 0..N {
        let out = Command::new("systemd-run")
            .args([
                "--quiet",
                "--wait",
                "--pipe",
                "--collect",
                "-p",
                "User=root",
                "-E",
            ])
            .arg(format!("LD_PRELOAD={}", lib.display()))
            .arg("-E")
            .arg(format!(
                "NN_E2E_PRELOAD_MARK={}",
                mark("service", i).display()
            ))
            .arg("/usr/bin/true")
            .stdin(Stdio::null())
            .output()
            .expect("spawn systemd-run");
        if out.status.success() {
            ran.entry(("service", i))
                .or_default()
                .push("the exec ran".into());
        }
        if mark("service", i).exists() {
            ran.entry(("service", i))
                .or_default()
                .push("the preload ran".into());
        }
    }
    stop.store(true, Ordering::Relaxed);
    for s in spinners {
        let _ = s.join();
    }
    let of = |who: &str| ran.keys().filter(|(w, _)| *w == who).count();
    assert!(
        ran.is_empty(),
        "{} staging-preload execs were not refused (root {}, nobody {}, service {}, of {N} each; \
         ia32 {}, x32 {}, of {} each; on {cpus} CPUs): {ran:#?}\nagent.log tail:\n{}",
        ran.len(),
        of("root"),
        of("nobody"),
        of("service"),
        of("ia32"),
        of("x32"),
        N / 3,
        tail(&fx.agent_log)
    );
}

/// A C program that execs `argv[1]` with `n` padding variables, then the
/// variables given after `--` (`NAME=value`), from a thread-free process;
/// exit 77 when the exec is refused (`EACCES`), 1 on another error. Lot 325
/// (the re-check of #546, R2).
fn compile_env_exec(dir: &Path) -> PathBuf {
    let src = dir.join("env_exec.c");
    std::fs::write(
        &src,
        r#"#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc < 3) return 2;
  /* "hi": no padding, execve entered with garbage in rax's high half (the
     kernel runs the low half; pt_regs->orig_ax keeps all 64 bits) */
  int hi = strcmp(argv[2], "hi") == 0;
  long pad = hi ? 0 : atol(argv[2]);
  int extra = argc - 3;
  char **envv = calloc(pad + extra + 1, sizeof(char *));
  if (!envv) return 3;
  for (long i = 0; i < pad; i++) {
    char *v = malloc(24);
    snprintf(v, 24, "NN_PAD_%ld=x", i);
    envv[i] = v;
  }
  for (int j = 0; j < extra; j++) envv[pad + j] = argv[3 + j];
  envv[pad + extra] = NULL;
  char *args[] = {argv[1], NULL};
#if defined(__x86_64__)
  if (hi) {
    long r;
    register long rdx __asm__("rdx") = (long)envv;
    __asm__ volatile("syscall"
                     : "=a"(r)
                     : "0"((1UL << 32) | 59), "D"(argv[1]), "S"(args), "r"(rdx)
                     : "rcx", "r11", "memory");
    errno = (int)-r;
    return errno == EACCES ? 77 : 1;
  }
#endif
  execve(argv[1], args, envv);
  return errno == EACCES ? 77 : 1;
}
"#,
    )
    .expect("write env_exec.c");
    let bin = dir.join("env_exec");
    let st = Command::new("cc")
        .args(["-O2", "-o"])
        .arg(&bin)
        .arg(&src)
        .status()
        .expect("spawn cc");
    assert!(st.success(), "cc failed");
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    bin
}

/// Lot 325 (the re-check of #546, R2): the scan read the first 64
/// variables only — 64 padding variables, then `LD_PRELOAD` from a staging
/// path, went through without a refusal and, for a root session, without
/// a record. With a table that refuses a staging preload in every tier,
/// the same exec behind 64, 65, 1,000 and 50,000 padding variables is
/// refused, as root and as `nobody`, and the preload never runs; so are a
/// staging entry past the first 128 bytes of a clean list and (as root) a
/// staging `LD_PRELOAD` followed by a clean one (musl's loader takes the
/// first) — the mini-hunt. The review of #547: the forms each passed —
/// 120 spaces before the entry, `//tmp/`, `/./tmp/` (F1), a relative path
/// (refused where a staging preload is: where it resolves is not in the
/// string), an `execve` entered with garbage in `rax`'s high half (F3);
/// an entry past the first pass's reads is killed at the post-commit check
/// (F7). The controls run: the padding without the preload, and long clean
/// values — a 2,880-byte `LD_PRELOAD`, a 2,880-byte `LD_LIBRARY_PATH` (F7:
/// a clean value past 128 bytes was refused). The re-check of #547
/// (G1–G4): a tab inside an `LD_PRELOAD` entry, an empty `LD_LIBRARY_PATH`
/// element (`:`, a trailing `:`), a `$LIB` token and a newline (musl's
/// library-path separator) are refused.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn a_staging_preload_behind_many_variables_is_refused() {
    use std::os::unix::process::CommandExt;
    let _eni = EniIptablesGuard::install();
    let fx = Fixture::setup_opts(None, Some("preload * deny\n"));
    let armed = common::wait_until(Duration::from_secs(30), || {
        std::fs::read_to_string(&fx.agent_log).ok().and_then(|l| {
            l.lines()
                .find(|l| l.contains("exec policy armed in the kernel") && l.contains("env=true"))
                .map(str::to_string)
        })
    });
    assert!(
        armed.is_some_and(|a| a.contains("enforce")),
        "the exec policy did not arm with the environment check; agent.log tail:\n{}",
        tail(&fx.agent_log)
    );
    let work = tempfile::Builder::new()
        .prefix("nn-e2e-325-")
        .tempdir_in("/tmp")
        .expect("tempdir under /tmp");
    std::fs::set_permissions(work.path(), std::fs::Permissions::from_mode(0o777))
        .expect("chmod the work directory");
    let lib = compile_marker_preload(work.path());
    let exe = compile_env_exec(work.path());
    let mark = |case: &str| work.path().join(format!("mark.{case}"));
    // `/usr/bin/true` itself with `pad` padding variables, then `vars`
    // (exec'd by this test: a helper of the test's own under /tmp is the
    // agent's `R001_ExecFromTmp` for `nobody`, killed); Err(errno) when the
    // exec is refused
    // (Ok: its exit code, 128 + the signal that killed it)
    let run_at = |cwd: Option<&Path>,
                  pad: usize,
                  vars: &[(String, String)],
                  uid: Option<u32>|
     -> Result<i32, i32> {
        let mut c = Command::new("/usr/bin/true");
        c.env_clear()
            .envs((0..pad).map(|i| (format!("NN_PAD_{i}"), "x".to_string())))
            .envs(vars.iter().cloned())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(d) = cwd {
            c.current_dir(d);
        }
        if let Some(u) = uid {
            c.uid(u).gid(u);
        }
        match c.status() {
            Ok(st) => Ok(st.code().unwrap_or_else(|| 128 + st.signal().unwrap_or(0))),
            Err(e) => Err(e.raw_os_error().unwrap_or(-1)),
        }
    };
    let run =
        |pad: usize, vars: &[(String, String)], uid: Option<u32>| run_at(None, pad, vars, uid);
    let preload = |case: &str, value: String| {
        vec![
            ("LD_PRELOAD".to_string(), value),
            (
                "NN_E2E_PRELOAD_MARK".to_string(),
                mark(case).display().to_string(),
            ),
        ]
    };
    let mut failures = Vec::new();
    for (who, uid) in [("root", None), ("nobody", Some(NOBODY))] {
        // controls: the padding alone runs (50,000 padding variables: about
        // 1.2 MB, inside the default stack limit's quarter)
        for pad in [64usize, 50_000] {
            let rc = run(pad, &[], uid);
            if rc != Ok(0) {
                failures.push(format!("{who}: {pad} padding variables alone: {rc:?}"));
            }
        }
        for pad in [0usize, 63, 64, 65, 1_000, 50_000] {
            let case = format!("{who}-{pad}");
            let rc = run(pad, &preload(&case, lib.display().to_string()), uid);
            if rc != Err(13) || mark(&case).exists() {
                failures.push(format!(
                    "{who}: a staging preload behind {pad} variables: {rc:?}, the preload \
                     ran: {}",
                    mark(&case).exists()
                ));
            }
        }
        // the mini-hunt: a staging entry past the first 128 bytes of a long
        // clean list (`LD_PRELOAD`'s capture)
        let case = format!("{who}-long");
        let long = format!(
            "{}:{}",
            ["/usr/lib/x86_64-linux-gnu/libc.so.6"; 5].join(":"),
            lib.display()
        );
        let rc = run(0, &preload(&case, long), uid);
        if rc != Err(13) || mark(&case).exists() {
            failures.push(format!(
                "{who}: a staging preload past 128 bytes of clean ones: {rc:?}"
            ));
        }
        // the review of #547 (F1): the forms the 9-byte compare missed
        let l = lib.display().to_string();
        for (tag, value) in [
            ("spaces", format!("{}{l}", " ".repeat(120))),
            ("slashes", format!("/{l}")),
            ("dot", format!("/.{l}")),
        ] {
            let case = format!("{who}-{tag}");
            let rc = run(0, &preload(&case, value), uid);
            if rc != Err(13) || mark(&case).exists() {
                failures.push(format!(
                    "{who}: a staging preload written {tag}: {rc:?}, the preload ran: {}",
                    mark(&case).exists()
                ));
            }
        }
        // a relative path (here, the staging directory's): refused where a
        // staging preload is
        let case = format!("{who}-relative");
        let rc = run_at(
            Some(work.path()),
            0,
            &preload(&case, "./libmark.so".to_string()),
            uid,
        );
        if rc != Err(13) || mark(&case).exists() {
            failures.push(format!("{who}: a relative preload: {rc:?}"));
        }
        // The re-check of #547 (G1–G4): what the loader does with a
        // control byte, an empty library-path element or a `$` token is not
        // in the string as the check reads it — refused at a protected
        // target, whatever the value names (glibc loaded the marker in G1–G3)
        for (tag, vars) in [
            (
                "tab",
                vec![("LD_PRELOAD".to_string(), "libmark.so\t/x.so".to_string())],
            ),
            (
                "empty-element",
                vec![
                    ("LD_LIBRARY_PATH".to_string(), ":".to_string()),
                    ("LD_PRELOAD".to_string(), "libmark.so".to_string()),
                ],
            ),
            (
                "trailing-element",
                vec![
                    ("LD_LIBRARY_PATH".to_string(), "/usr/lib:".to_string()),
                    ("LD_PRELOAD".to_string(), "libmark.so".to_string()),
                ],
            ),
            (
                "dst",
                vec![(
                    "LD_PRELOAD".to_string(),
                    "/usr/$LIB/libc.so.6".to_string(),
                )],
            ),
            (
                "newline",
                vec![(
                    "LD_LIBRARY_PATH".to_string(),
                    "/usr/lib\n/opt/lib".to_string(),
                )],
            ),
        ] {
            let case = format!("{who}-{tag}");
            let mut v = vars;
            v.push((
                "NN_E2E_PRELOAD_MARK".to_string(),
                mark(&case).display().to_string(),
            ));
            let rc = run_at(Some(work.path()), 0, &v, uid);
            if rc != Err(13) || mark(&case).exists() {
                failures.push(format!(
                    "{who}: an irregular loader value ({tag}): {rc:?}, the preload ran: {}",
                    mark(&case).exists()
                ));
            }
        }
        // F7: past the first pass's reads (about 4 KiB), the entry is
        // judged on the kernel's copy after the commit: killed
        let case = format!("{who}-past-reads");
        let far = format!(
            "{}:{l}",
            ["/usr/lib/x86_64-linux-gnu/libc.so.6"; 120].join(":")
        );
        let rc = run(0, &preload(&case, far), uid);
        if rc != Ok(128 + 9) || mark(&case).exists() {
            failures.push(format!(
                "{who}: a staging preload past the first pass's reads: {rc:?}, the preload \
                 ran: {}",
                mark(&case).exists()
            ));
        }
        // the controls: long clean values run
        let clean = ["/usr/lib/x86_64-linux-gnu/libc.so.6"; 80].join(":");
        for (name, value) in [("LD_PRELOAD", &clean), ("LD_LIBRARY_PATH", &clean)] {
            let rc = run(0, &[(name.to_string(), value.clone())], uid);
            if rc != Ok(0) {
                failures.push(format!(
                    "{who}: a clean {name} of {} bytes: {rc:?}",
                    value.len()
                ));
            }
        }
    }
    // the mini-hunt: a staging preload first, a clean one last (two
    // `LD_PRELOAD` entries, which only a raw `envp` can carry: the helper,
    // as root — the agent's `R009` on a root exec from /tmp only logs)
    let st = Command::new(&exe)
        .arg("/usr/bin/true")
        .arg("70")
        .arg(format!("LD_PRELOAD={}", lib.display()))
        .arg(format!("NN_E2E_PRELOAD_MARK={}", mark("first").display()))
        .arg("LD_PRELOAD=libc.so.6")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn env_exec");
    if st.code() != Some(77) {
        failures.push(format!(
            "root: a staging preload followed by a clean one: {st:?}"
        ));
    }
    // the review of #547 (F3): `execve` entered with garbage in `rax`'s
    // high half — the kernel runs it; the scan read no environment
    #[cfg(target_arch = "x86_64")]
    {
        let st = Command::new(&exe)
            .arg("/usr/bin/true")
            .arg("hi")
            .arg(format!("LD_PRELOAD={}", lib.display()))
            .arg(format!("NN_E2E_PRELOAD_MARK={}", mark("hi").display()))
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn env_exec");
        if st.code() != Some(77) || mark("hi").exists() {
            failures.push(format!(
                "root: an execve with rax's high half set: {st:?}, the preload ran: {}",
                mark("hi").exists()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{failures:#?}\nagent.log tail:\n{}",
        tail(&fx.agent_log)
    );
}

/// Lot 325 (the re-check of #546, R5): the exec guards' per-task maps full —
/// the shape of a fork bomb's flood of execs in flight, made here by the
/// agent itself (`debug-execpol-fill`, `debug-trigger` builds) so that it
/// is bounded and deterministic. Lot 322 refused every exec then. The
/// server profile (a session's staging preload refused for root): with the
/// walk's map full, a plain exec runs as root and as `nobody`, and a burst
/// of 256 of them from 16 threads runs whole; a staging preload as root
/// and a memfd as root (a deny cell without a walk) are still refused.
/// With the environment's map full too (the review of #547, F5: root's
/// plain exec and `su` were refused then — every service exec on a server),
/// `nobody`'s, root's and a set-id program's as `nobody` (`su`) plain
/// execs run; root's staging preload, which the first pass could not read,
/// is killed at the post-commit check (the kernel's copy, read into a
/// per-CPU buffer the flood cannot take) before its first instruction.
/// Emptied, the exec policy judges as before. The agent signs a
/// degradation (`execpol_capacity`) meanwhile.
#[cfg(feature = "debug-trigger")]
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn the_exec_guards_past_their_capacity_keep_protected_targets_closed() {
    use std::os::unix::process::CommandExt;
    let _eni = EniIptablesGuard::install();
    // the server profile, made the same in every tier the test may run in:
    // root's staging preloads refused, a memfd refused
    let fx = Fixture::setup_opts(
        None,
        Some("profile server\npreload * deny-root\nexec memfd * deny\n"),
    );
    let armed = common::wait_until(Duration::from_secs(30), || {
        std::fs::read_to_string(&fx.agent_log).ok().and_then(|l| {
            l.lines()
                .find(|l| l.contains("exec policy armed in the kernel") && l.contains("env=true"))
                .map(str::to_string)
        })
    });
    assert!(
        armed.is_some_and(|a| a.contains("enforce")),
        "the exec policy did not arm; agent.log tail:\n{}",
        tail(&fx.agent_log)
    );
    let work = tempfile::Builder::new()
        .prefix("nn-e2e-325c-")
        .tempdir_in("/tmp")
        .expect("tempdir under /tmp");
    std::fs::set_permissions(work.path(), std::fs::Permissions::from_mode(0o777))
        .expect("chmod the work directory");
    let lib = compile_marker_preload(work.path());
    let dir = fx
        .admin_socket
        .parent()
        .expect("the socket's directory")
        .to_path_buf();
    let trigger = |name: &str, text: &str, log: &str| {
        let t = dir.join(name);
        let before = std::fs::read_to_string(&fx.agent_log)
            .map(|l| l.matches(log).count())
            .unwrap_or(0);
        std::fs::write(&t, text).expect("write the trigger");
        let taken = common::wait_until(Duration::from_secs(15), || {
            std::fs::read_to_string(&fx.agent_log)
                .ok()
                .filter(|l| !t.exists() && l.matches(log).count() > before)
                .map(|_| ())
        });
        assert!(taken.is_some(), "the agent did not take {name}");
    };
    // 0: ran, 13: refused (EACCES), other: the error
    let exec = |path: &str, args: &[&str], uid: Option<u32>, env: &[(&str, String)]| -> i32 {
        let mut c = Command::new(path);
        c.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (k, v) in env {
            c.env(k, v);
        }
        if let Some(u) = uid {
            c.uid(u).gid(u);
        }
        match c.spawn() {
            Ok(mut ch) => {
                let _ = ch.wait();
                0
            }
            Err(e) => e.raw_os_error().unwrap_or(-1),
        }
    };
    let staging = vec![("LD_PRELOAD", lib.display().to_string())];
    let memfd_true = || -> i32 {
        // /usr/bin/true copied into a memfd and run from it, as root
        let out = Command::new("python3")
            .args([
                "-I",
                "-c",
                "import os,sys\nfd=os.memfd_create('nn325')\nos.write(fd,open('/usr/bin/true','rb').read())\n\
                 try:\n    os.execve(fd,['true'],{})\nexcept PermissionError:\n    sys.exit(77)\n",
            ])
            .stdin(Stdio::null())
            .status()
            .expect("spawn python3");
        out.code().unwrap_or(-1)
    };
    let mut fails: Vec<String> = Vec::new();
    fn want(fails: &mut Vec<String>, what: &str, got: i32, want: i32) {
        if got != want {
            fails.push(format!("{what}: {got}, wanted {want}"));
        }
    }
    // the policy before the flood: a staging preload as root is refused
    want(
        &mut fails,
        "before: root, staging preload",
        exec("/usr/bin/true", &[], None, &staging),
        13,
    );
    want(
        &mut fails,
        "before: root, plain",
        exec("/usr/bin/true", &[], None, &[]),
        0,
    );

    // the walk's map full
    trigger(
        "debug-execpol-fill",
        "walk",
        "the exec guards' per-task maps filled",
    );
    want(
        &mut fails,
        "walk full: root, plain",
        exec("/usr/bin/true", &[], None, &[]),
        0,
    );
    want(
        &mut fails,
        "walk full: nobody, plain",
        exec("/usr/bin/true", &[], Some(NOBODY), &[]),
        0,
    );
    want(
        &mut fails,
        "walk full: root, staging preload",
        exec("/usr/bin/true", &[], None, &staging),
        13,
    );
    want(&mut fails, "walk full: root, a memfd", memfd_true(), 77);
    // a burst, bounded: 16 threads x 16 plain execs, every one runs
    let refused: usize = std::thread::scope(|sc| {
        let hs: Vec<_> = (0..16)
            .map(|_| {
                sc.spawn(|| {
                    (0..16)
                        .filter(|_| exec("/usr/bin/true", &[], None, &[]) != 0)
                        .count()
                })
            })
            .collect();
        hs.into_iter()
            .map(|h| h.join().expect("burst thread"))
            .sum()
    });
    want(
        &mut fails,
        "walk full: a burst of 256 plain execs, refused",
        refused as i32,
        0,
    );

    // the environment's map full too
    trigger(
        "debug-execpol-empty",
        "",
        "the exec guards' per-task maps emptied",
    );
    trigger(
        "debug-execpol-fill",
        "walk env",
        "the exec guards' per-task maps filled",
    );
    want(
        &mut fails,
        "both full: nobody, plain",
        exec("/usr/bin/true", &[], Some(NOBODY), &[]),
        0,
    );
    want(
        &mut fails,
        "both full: root, plain (protected)",
        exec("/usr/bin/true", &[], None, &[]),
        0,
    );
    if Path::new("/usr/bin/su").exists() {
        want(
            &mut fails,
            "both full: nobody, su (set-id)",
            exec("/usr/bin/su", &["--version"], Some(NOBODY), &[]),
            0,
        );
    }
    // root's staging preload: let through unread, killed after the commit
    let killed_mark = work.path().join("mark.both-full");
    let st = Command::new("/usr/bin/true")
        .env("LD_PRELOAD", lib.display().to_string())
        .env("NN_E2E_PRELOAD_MARK", killed_mark.display().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match st {
        Ok(st) if st.signal() == Some(9) && !killed_mark.exists() => {}
        other => fails.push(format!(
            "both full: root, staging preload: {other:?}, the preload ran: {}",
            killed_mark.exists()
        )),
    }

    // emptied: as before
    trigger(
        "debug-execpol-empty",
        "",
        "the exec guards' per-task maps emptied",
    );
    want(
        &mut fails,
        "after: root, plain",
        exec("/usr/bin/true", &[], None, &[]),
        0,
    );
    want(
        &mut fails,
        "after: root, staging preload",
        exec("/usr/bin/true", &[], None, &staging),
        13,
    );
    // the capacity episode is signed
    let degraded = common::wait_until(Duration::from_secs(10), || {
        std::fs::read_to_string(&fx.agent_log)
            .ok()
            .filter(|l| l.contains("execpol_capacity"))
            .map(|_| ())
    });
    if degraded.is_none() {
        fails.push("no execpol_capacity degradation in the agent's log".into());
    }
    assert!(
        fails.is_empty(),
        "{fails:#?}\nagent.log tail:\n{}",
        tail(&fx.agent_log)
    );
}

/// Lot 325 (TOCTOU; the review of #546, F2): the first pass reads the
/// caller's memory after the kernel copied it. A child of this test execs
/// `/usr/bin/true` with `LD_PRELOAD` from a staging path while a thread of
/// its own flips the variable's first byte (`L` / `X`) as fast as it can:
/// the kernel's copy and the first pass's read can disagree. Whatever each
/// read saw, the preload never runs: refused at the first pass (`EACCES`),
/// or killed before its first instruction by the post-commit check (the
/// kernel's own copy), or the copy held `XD_PRELOAD` and nothing loaded.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn a_preload_written_after_the_kernel_s_copy_never_runs() {
    const N: usize = 300;
    let _eni = EniIptablesGuard::install();
    let fx = Fixture::setup_opts(None, Some("preload * deny\n"));
    let armed = common::wait_until(Duration::from_secs(30), || {
        std::fs::read_to_string(&fx.agent_log).ok().and_then(|l| {
            l.lines()
                .find(|l| l.contains("exec policy armed in the kernel") && l.contains("env=true"))
                .map(str::to_string)
        })
    });
    assert!(
        armed.is_some(),
        "not armed; agent.log tail:\n{}",
        tail(&fx.agent_log)
    );
    let work = tempfile::Builder::new()
        .prefix("nn-e2e-325t-")
        .tempdir_in("/tmp")
        .expect("tempdir under /tmp");
    std::fs::set_permissions(work.path(), std::fs::Permissions::from_mode(0o777))
        .expect("chmod the work directory");
    let lib = compile_marker_preload(work.path());
    let racer = compile_flip_exec(work.path());
    let (mut refused, mut killed, mut clean, mut ran) = (0, 0, 0, Vec::new());
    for i in 0..N {
        let mark = work.path().join(format!("mark.{i}"));
        let st = Command::new(&racer)
            .arg(&lib)
            .arg(&mark)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn flip_exec");
        match (st.code(), st.signal()) {
            (Some(77), _) => refused += 1,
            (None, Some(9)) => killed += 1,
            _ => clean += 1,
        }
        if mark.exists() {
            ran.push(i);
        }
    }
    eprintln!(
        "flip race, {N} execs: refused at the first pass {refused}, killed past the point of no \
         return {killed}, ran without the preload {clean}, ran with it {}",
        ran.len()
    );
    assert!(
        ran.is_empty(),
        "the preload ran in {} of {N} execs ({ran:?}); refused {refused}, killed {killed}\n\
         agent.log tail:\n{}",
        ran.len(),
        tail(&fx.agent_log)
    );
}

/// The race of [`a_preload_written_after_the_kernel_s_copy_never_runs`]: a
/// thread flips the first byte of `LD_PRELOAD=<lib>` while the main thread
/// execs `/usr/bin/true` with it; exit 77 when the exec is refused.
fn compile_flip_exec(dir: &Path) -> PathBuf {
    let src = dir.join("flip_exec.c");
    std::fs::write(
        &src,
        r#"#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static char pre[512];
static volatile int go;
static void *flip(void *a) {
  (void)a;
  go = 1;
  for (;;) { pre[0] = 'X'; __sync_synchronize(); pre[0] = 'L'; __sync_synchronize(); }
  return NULL;
}
int main(int argc, char **argv) {
  if (argc < 3) return 2;
  snprintf(pre, sizeof pre, "LD_PRELOAD=%s", argv[1]);
  static char mk[512];
  snprintf(mk, sizeof mk, "NN_E2E_PRELOAD_MARK=%s", argv[2]);
  char *envv[] = {pre, mk, NULL};
  char *args[] = {"true", NULL};
  pthread_t t;
  if (pthread_create(&t, NULL, flip, NULL)) return 3;
  while (!go) {}
  execve("/usr/bin/true", args, envv);
  return errno == EACCES ? 77 : 1;
}
"#,
    )
    .expect("write flip_exec.c");
    let bin = dir.join("flip_exec");
    let st = Command::new("cc")
        .args(["-O2", "-pthread", "-o"])
        .arg(&bin)
        .arg(&src)
        .status()
        .expect("spawn cc");
    assert!(st.success(), "cc failed");
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    bin
}
