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

    // the control: the same exec without the preload runs
    let st = Command::new("/usr/bin/true").status().expect("spawn true");
    assert!(st.success(), "/usr/bin/true without a preload: {st}");

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
        "{} of {} staging-preload execs were not refused (root {}, nobody {}, service {}, of {N} \
         each; on {cpus} CPUs): {ran:#?}\nagent.log tail:\n{}",
        ran.len(),
        3 * N,
        of("root"),
        of("nobody"),
        of("service"),
        tail(&fx.agent_log)
    );
}
