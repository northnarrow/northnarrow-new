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
//!   (the offender's parent), run on.
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

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::EniIptablesGuard;

const SOCKET_POLL_TIMEOUT: Duration = Duration::from_secs(15);
const RECORD_POLL_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const BPFFS_PIN_ROOT: &str = "/sys/fs/bpf/northnarrow";

fn agent_bin() -> &'static str {
    env!("CARGO_BIN_EXE_northnarrow-agent")
}
fn nn_admin_bin() -> &'static str {
    env!("CARGO_BIN_EXE_nn-admin")
}
fn configs() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("configs")
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

/// An enforcing agent with every state file in a per-test tempdir, empty
/// allow/blocklists, no FIM watch, ADE off.
struct Fixture {
    _tempdir: tempfile::TempDir,
    agent_log: PathBuf,
    detections_log: PathBuf,
    _agent_guard: AgentGuard,
}

impl Fixture {
    fn setup() -> Self {
        wipe_pin_tree();
        let tempdir = tempfile::tempdir().expect("tempdir");
        let dir = tempdir.path().to_path_buf();

        // Before the agent runs: nn-admin is not exec'd again afterwards.
        let status = Command::new(nn_admin_bin())
            .arg("init")
            .arg("--priv-out")
            .arg(dir.join("admin.priv"))
            .arg("--pub-append")
            .arg(dir.join("admin.pub"))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .expect("spawn nn-admin init");
        assert!(status.success(), "nn-admin init failed");

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

        let agent_log = dir.join("agent.log");
        let detections_log = dir.join("detections.jsonl");
        let log = std::fs::File::create(&agent_log).expect("create agent.log");
        let log_err = log.try_clone().expect("clone agent.log");
        let mut cmd = Command::new(agent_bin());
        cmd.arg("--combat-rules")
            .arg(&combat)
            .arg("--admin-pub")
            .arg(dir.join("admin.pub"))
            .arg("--admin-socket")
            .arg(dir.join("admin.sock"))
            .arg("--agent-id-file")
            .arg(dir.join("agent_id"))
            .arg("--audit-log-file")
            .arg(dir.join("audit.log"))
            .arg("--signing-key-file")
            .arg(dir.join("agent.sig.key"))
            .arg("--shutdown-marker-file")
            .arg(dir.join("agent.shutdown_authorised"))
            .arg("--detections-file")
            .arg(&detections_log)
            .arg("--status-events-file")
            .arg(dir.join("status_events.jsonl"))
            .arg("--fim-paths-v1")
            .arg(empty("fim-paths.v1"))
            .arg("--fim-paths-local")
            .arg(empty("fim-paths.local"))
            .arg("--fim-baseline-file")
            .arg(dir.join("fim_baseline.jsonl"))
            .arg("--fim-drift-file")
            .arg(dir.join("fim_drift.jsonl"))
            .arg("--canary-registry-file")
            .arg(dir.join("canaries.jsonl"))
            .arg("--canary-access-file")
            .arg(dir.join("canary_access.jsonl"))
            .arg("--canary-template-dir")
            .arg(&templates)
            .arg("--netflow-file")
            .arg(dir.join("netflow.jsonl"))
            .arg("--netflow-listeners-file")
            .arg(dir.join("netflow_listeners.jsonl"));
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
            .arg("--no-ade")
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()
            .expect("spawn northnarrow-agent for the response e2e");
        let guard = AgentGuard(Some(child));

        let socket = dir.join("admin.sock");
        let deadline = Instant::now() + SOCKET_POLL_TIMEOUT;
        while !socket.exists() {
            assert!(
                Instant::now() < deadline,
                "agent never opened its admin socket; agent.log tail:\n{}",
                tail(&agent_log)
            );
            std::thread::sleep(POLL_INTERVAL);
        }

        Self {
            _tempdir: tempdir,
            agent_log,
            detections_log,
            _agent_guard: guard,
        }
    }

    /// The detection record of the process `pid`.
    fn wait_record_of(&self, pid: u32) -> serde_json::Value {
        let pid = u64::from(pid);
        common::wait_until(RECORD_POLL_TIMEOUT, || {
            common::jsonl_rows(&self.detections_log)
                .into_iter()
                .find(|r| r["principal"]["pid"].as_u64() == Some(pid))
        })
        .unwrap_or_else(|| {
            panic!(
                "no detection record of pid {pid} within {RECORD_POLL_TIMEOUT:?}; records: {:?}\n\
                 agent.log tail:\n{}",
                common::jsonl_rows(&self.detections_log),
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
    let bin = dir.path().join("sleep");
    std::fs::copy("/bin/sleep", &bin).expect("copy /bin/sleep");
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    (dir, bin)
}

/// (a) An exec from `/tmp` (R001, or the exec rule that matches it first;
/// a kill either way) by a child of the harness. A decoy with the same
/// name and the same parent runs beside it. The record names the offender
/// and the bare action name (carried out); the offender died by SIGKILL;
/// the decoy and the harness run on.
///
/// Regressions it catches: a kill aimed at the parent kills the harness;
/// at the wrong process (by name), the decoy; recorded but not landed, the
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
    let mut offender = Spawned(
        Command::new(&bin)
            .arg("120")
            .stdout(Stdio::null())
            .spawn()
            .expect("exec the /tmp offender"),
    );
    let pid = offender.0.id();

    let rec = fx.wait_record_of(pid);
    assert_eq!(rec["exe"].as_str(), bin.to_str(), "record: {rec}");
    let action = rec["verdict"]["Rule"].as_str();
    assert!(
        matches!(action, Some("KillProcess" | "KillProcessTree")),
        "a kill was expected; record: {rec}"
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
    let decoy_records: Vec<_> = common::jsonl_rows(&fx.detections_log)
        .into_iter()
        .filter(|r| r["principal"]["pid"].as_u64() == Some(decoy_pid))
        .collect();
    assert!(decoy_records.is_empty(), "decoy records: {decoy_records:?}");
}
