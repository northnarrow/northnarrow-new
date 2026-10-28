//! Tappa 9.5 K8 — privileged end-to-end tests for the canary
//! deception layer (CLOSES TAPPA 9.5).
//!
//! Spawns the real `northnarrow-agent` binary against a per-test
//! tempdir, deploys a canary via a signed `nn-admin canary deploy`
//! call, simulates the access that should trip it, then asserts
//! the resulting row in the chained `canary_access.jsonl`. Verifies
//! end-to-end on a real kernel that:
//!
//! - K3 detector observes the kernel-side event (FIM `inode_file_open`
//!   for file canaries; `sched_process_exec` for process canaries),
//! - the inline-filter precedence path replaces the source event with
//!   `Event::CanaryTripped` (so the rule engine routes through the
//!   K5 NN-L-CANARY-001 / 002 rule, NOT the FIM / R009 rule),
//! - the access log append fires with `first_trip = true` on the
//!   first trip,
//! - `Registry::refresh` correctly clears the tripped flag so a
//!   subsequent access fires AGAIN as `first_trip = true` (the
//!   §12 Q2 + §7.4 MANUAL-REFRESH contract);
//! - external audit DEC-011: a trip is recorded in the registry and
//!   survives an agent restart;
//! - lab PR 260: a trip survives an agent stopped between its access row
//!   and the registry's `Trip` row (the `debug-trigger` failpoint): the next
//!   start records it from the access row;
//! - external audit DEC-010: a decoy changed while the agent is down is
//!   reported at the next start (signed `integrity_drift`, `decoy_check`
//!   row);
//! - external audit DEC-007 / DEC-008: a credential decoy names nothing
//!   and is a new one at every deploy and refresh.
//!
//! Posture transition to COMBAT + the iptables `NORTHNARROW_COMBAT`
//! chain are NOT asserted here — those are exercised by the existing
//! Tappa 8 `privileged_e2e.rs` shutdown / force-posture tests against
//! the same dispatch path. K8's scope is the canary-specific wire:
//! kernel observe → detector intercept → chained access-log append
//! → refresh re-arm. The K5 rule unit tests already pin that every
//! `Event::CanaryTripped` produces `ResponseAction::KillProcessTree`
//! with `Severity::Critical` (which the posture FSM translates to
//! Combat).
//!
//! Requirements (operator-runnable per
//! `docs/integration-test-runbook.md`):
//! - root (or CAP_SYS_ADMIN + CAP_NET_ADMIN);
//! - kernel with `bpf` in `/sys/kernel/security/lsm`;
//! - `/sys/fs/bpf` mounted as bpffs;
//! - workspace built `--release --features test-privileged`;
//! - no production agent currently holding the
//!   `/sys/fs/bpf/northnarrow` pin tree (kill it first).
//!
//! Run:
//!   sudo -E env "PATH=$PATH" cargo test --release --workspace --tests \
//!     --features "test-privileged debug-trigger" \
//!     -- --include-ignored --test-threads=1 canary_privileged

#![cfg(feature = "test-privileged")]

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::agent_state::{AgentState, InstalledAgent, Launch};
use common::{install_to_priv_bin, EniIptablesGuard, InstalledBin};

const SOCKET_POLL_TIMEOUT: Duration = Duration::from_secs(15);
const ACCESS_LOG_POLL_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

fn nn_admin_bin() -> &'static str {
    env!("CARGO_BIN_EXE_nn-admin")
}

fn combat_rules_path() -> PathBuf {
    PathBuf::from(env!("NN_REPO_ROOT"))
        .join("configs")
        .join("combat-rules.v4")
}

fn canary_templates_dir() -> PathBuf {
    PathBuf::from(env!("NN_REPO_ROOT"))
        .join("configs")
        .join("canary-templates")
}

/// Stops the agent on drop (`common::quit_agent`: evicts the sudo subtree
/// from PROTECTED_PIDS, then SIGQUITs it; the task_kill hook refuses every
/// signal from the test runner while the pid is protected). An agent that
/// survives fails the test.
struct AgentGuard(Option<Child>);

impl Drop for AgentGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            // Unprotect + SIGQUIT the whole sudo subtree, bounded wait
            // (sudo 1.9.9 does not relay our signal, see common::quit_agent).
            common::quit_agent(&mut c);
        }
    }
}

/// K8.1 R009 avoidance: agent + nn-admin run from root-owned copies
/// under `/usr/local/bin/` (`InstalledAgent`, `common::install_to_priv_bin`),
/// so the post-spawn nn-admin canary deploy / refresh calls don't trip the
/// agent's `R009_RootExecFromUserPath` rule (which kills any root spawn
/// originating from `/home/`, `/tmp/`, `/var/tmp/`).
fn install_priv_bins() -> (InstalledAgent, InstalledBin) {
    let installed_agent = InstalledAgent::install();
    let installed_admin = install_to_priv_bin(Path::new(nn_admin_bin()));
    (installed_agent, installed_admin)
}

/// Production-pinned bpffs root the agent writes to. Wiped per-test
/// so each agent boots with a clean program + map pin tree
/// (mirrors `fim_privileged_e2e::wipe_pin_tree`).
const BPFFS_PIN_ROOT: &str = "/sys/fs/bpf/northnarrow";

fn wipe_pin_tree() {
    let pin = Path::new(BPFFS_PIN_ROOT);
    if !pin.exists() {
        return;
    }
    if let Ok(entries) = std::fs::read_dir(pin) {
        for entry in entries.flatten() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    let _ = std::fs::remove_dir(pin);
}

/// Tempdir + spawned-agent fixture for canary e2e. Holding every
/// per-test file path in one struct keeps the deploy + trip
/// helpers readable.
struct CanaryFixture {
    _tempdir: tempfile::TempDir,
    /// Per-test operator key (mode 0600, `all`-role line written
    /// into admin.pub).
    admin_priv: PathBuf,
    agent_id_file: PathBuf,
    admin_socket: PathBuf,
    /// Chain file the e2e tests assert against.
    canary_access_log: PathBuf,
    /// The registry chain and the audit log.
    canary_registry: PathBuf,
    audit_log: PathBuf,
    /// Lab PR 163: the per-test detection chain (the verdicts' records).
    detections_log: PathBuf,
    /// K8.1 R009 avoidance: the `/usr/local/bin/` installed
    /// nn-admin path. Every nn-admin subprocess spawn (deploy,
    /// refresh, init) routes through this path so R009 doesn't
    /// kill the op mid-flight. Kept alive by `_installed_admin`.
    nn_admin_path: PathBuf,
    /// The agent's state and its other arguments, to start it again
    /// ([`CanaryFixture::restart`]).
    state: AgentState,
    agent_args: Vec<std::ffi::OsString>,
    /// Drop order: AgentGuard first (SIGQUIT the agent), then
    /// the InstalledBin handles (sudo rm the /usr/local/bin/
    /// copies). Rust drops struct fields in declaration order,
    /// so keep `_agent_guard` BEFORE the installed-bin RAII
    /// handles so the agent is gone before we yank its binary.
    _agent_guard: AgentGuard,
    _installed_agent: InstalledAgent,
    _installed_admin: InstalledBin,
}

/// Lab PR 163: the agent stops before the fields drop. Fields drop in
/// declaration order, so `_tempdir` went first, with the agent still up;
/// since the records, flows and listeners live in the tempdir (signed
/// chains the agent protects), the removal was an unlink of a protected
/// inode by this test — a tamper the agent answered (COMBAT, the runner
/// killed, the guest isolated: Debian 12 gate of the lab follow-ups).
impl Drop for CanaryFixture {
    fn drop(&mut self) {
        self.stop();
    }
}

impl CanaryFixture {
    /// Spawn an agent with the canary subsystem wired against a
    /// per-test tempdir layout. `prewatched_files` is the list
    /// of file-canary decoy paths to seed into fim-paths.v1
    /// BEFORE spawn — the kernel `inode_file_open` LSM hook
    /// only fires for inodes in `WATCHED_PATHS`, and the agent
    /// loads WATCHED_PATHS once at boot from fim-paths.v1.
    /// Process canary tests pass an empty list (sched_process_exec
    /// isn't gated by WATCHED_PATHS).
    ///
    /// The admin key is minted before spawn so the agent reads
    /// a populated admin.pub at boot (any signed canary op
    /// below uses the same key).
    fn setup(prewatched_files: &[&Path]) -> Self {
        wipe_pin_tree();
        let tempdir = tempfile::tempdir().expect("tempdir");
        let dir = tempdir.path().to_path_buf();

        // K8.1 R009 avoidance: install agent + nn-admin under
        // /usr/local/bin/ BEFORE we touch any binary. The init
        // call below uses the installed nn-admin (R009 doesn't
        // fire pre-spawn but keeping every nn-admin call uniform
        // on the installed path avoids surprises if init starts
        // doing anything the agent observes later).
        let (installed_agent, installed_admin) = install_priv_bins();
        let nn_admin_path = installed_admin.path.clone();

        // Per-test admin keypair. nn-admin `init` writes a
        // role-less pub line (defaults to unlock + audit-read),
        // which isn't enough for canary ops; we re-write the
        // admin.pub line below with `all` so canary-manage +
        // canary-read both verify.
        // Lab PR 256: every file the agent writes in the tempdir.
        let state = AgentState::new(&dir);
        let admin_pub = state.admin_pub();
        let admin_priv = dir.join("admin.priv");
        let tmp_pub = dir.join("admin.pub.tmp");
        let init_status = Command::new(&nn_admin_path)
            .arg("init")
            .arg("--priv-out")
            .arg(&admin_priv)
            .arg("--pub-append")
            .arg(&tmp_pub)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .expect("spawn nn-admin init");
        assert!(init_status.success(), "nn-admin init failed");
        // Extract the 64-hex pubkey from the nn-admin init output
        // (one comment line + one hex line per design) and
        // re-write admin.pub with `all` role suffix so canary
        // ops verify.
        let tmp_body = std::fs::read_to_string(&tmp_pub).expect("read tmp pubkey");
        let hex = tmp_body
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .expect("init pub file has no hex line");
        assert_eq!(hex.len(), 64, "init pub file's hex line is not 64 chars");
        let mut pub_file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&admin_pub)
            .expect("create admin.pub");
        writeln!(pub_file, "{hex} all").expect("write admin.pub line");
        drop(pub_file);
        let _ = std::fs::remove_file(&tmp_pub);

        // Combat rules — copy verbatim; not exercised by these
        // tests but the agent refuses to spawn without them.
        let combat = dir.join("combat-rules.v4");
        std::fs::copy(combat_rules_path(), &combat).expect("copy combat rules");

        // FIM paths config: pre-bake the file-canary decoy
        // paths so the kernel `inode_file_open` LSM hook fires
        // on opens of those inodes. Process-canary tests pass
        // an empty list — sched_process_exec isn't gated by
        // WATCHED_PATHS.
        let fim_paths_v1 = dir.join("fim-paths.v1");
        {
            let mut f = std::fs::File::create(&fim_paths_v1).expect("create fim-paths.v1");
            for p in prewatched_files {
                writeln!(f, "{}", p.to_string_lossy()).expect("write fim-paths.v1 line");
            }
        }
        let fim_paths_local = dir.join("fim-paths.local");
        std::fs::write(&fim_paths_local, "").expect("write fim-paths.local");

        // Per-test canary template dir — operator-customised
        // copy so the agent can render canary content. K6 only
        // needs the template dir for File + Credential canary
        // materialisation; we ship the workspace defaults so
        // any future cred-canary e2e drop-in inherits the same
        // shape.
        let templates_dir = dir.join("canary-templates");
        std::fs::create_dir(&templates_dir).expect("mkdir canary-templates");
        let src_dir = canary_templates_dir();
        for entry in std::fs::read_dir(&src_dir).expect("read configs/canary-templates") {
            let entry = entry.expect("template dirent");
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("tmpl") {
                let basename = path.file_name().expect("template basename");
                std::fs::copy(&path, templates_dir.join(basename)).expect("copy template");
            }
        }

        let audit_log = state.audit_log();
        let agent_id = state.agent_id_file();
        let admin_socket = state.admin_socket();
        let canary_registry = state.canary_registry();
        let canary_access = state.canary_access();
        let detections_log = state.detections();

        // K8.1 R009 avoidance: spawn the installed /usr/local/bin/
        // agent via sudo. Mirrors `agent/tests/privileged_e2e.rs`
        // `spawn_agent_b5_with_installs`; sudo is a no-op when the
        // test process is already root (the runbook's `sudo -E
        // cargo test` invocation) but lets the test work under any
        // privilege-elevation flow that authorises sudo for the
        // user.
        // The state files are the helper's (`AgentState::args`); these are
        // the inputs.
        let agent_args: Vec<std::ffi::OsString> = [
            "--combat-rules".into(),
            combat.clone().into_os_string(),
            "--fim-paths-v1".into(),
            fim_paths_v1.clone().into_os_string(),
            "--fim-paths-local".into(),
            fim_paths_local.clone().into_os_string(),
            "--canary-template-dir".into(),
            templates_dir.clone().into_os_string(),
        ]
        .to_vec();
        common::require_bpftool();
        let child = installed_agent
            .command(&state, Launch::Sudo, &[common::OWN_DEFAULT_LISTS_ENV])
            .args(&agent_args)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn northnarrow-agent for canary e2e");
        let guard = AgentGuard(Some(child));

        wait_for_socket(&admin_socket);

        Self {
            _tempdir: tempdir,
            admin_priv,
            agent_id_file: agent_id,
            admin_socket,
            canary_access_log: canary_access,
            canary_registry,
            audit_log,
            detections_log,
            nn_admin_path,
            state,
            agent_args,
            _agent_guard: guard,
            _installed_agent: installed_agent,
            _installed_admin: installed_admin,
        }
    }

    /// Stop the agent and start it again with the same arguments: its
    /// state (registry, keys, logs) stays, its in-memory indexes and the
    /// kernel watches it registers are rebuilt from it.
    fn restart(&mut self) {
        self.stop();
        self.start();
    }

    /// Stop the agent (its state stays).
    fn stop(&mut self) {
        drop(std::mem::replace(&mut self._agent_guard, AgentGuard(None)));
        let _ = std::fs::remove_file(&self.admin_socket);
    }

    /// Start the agent again after [`CanaryFixture::stop`].
    fn start(&mut self) {
        common::require_bpftool();
        let child = self
            ._installed_agent
            .command(&self.state, Launch::Sudo, &[common::OWN_DEFAULT_LISTS_ENV])
            .args(&self.agent_args)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("respawn northnarrow-agent for canary e2e");
        self._agent_guard = AgentGuard(Some(child));
        wait_for_socket(&self.admin_socket);
    }

    /// Submit a signed `nn-admin canary deploy file --path <file>`
    /// op against the running agent. Returns the per-canary stable
    /// id parsed from the success line (`canary deploy: success
    /// (<id>)`).
    fn deploy_file_canary(&self, name: &str, decoy_path: &Path) -> String {
        let out = Command::new(&self.nn_admin_path)
            .arg("canary")
            .arg("deploy")
            .arg("--name")
            .arg(name)
            .arg("--key")
            .arg(&self.admin_priv)
            .arg("--agent-id-file")
            .arg(&self.agent_id_file)
            .arg("--socket")
            .arg(&self.admin_socket)
            .arg("file")
            .arg("--path")
            .arg(decoy_path)
            .stderr(Stdio::inherit())
            .output()
            .expect("spawn nn-admin canary deploy file");
        assert!(
            out.status.success(),
            "nn-admin canary deploy file: exit {:?}, stdout {:?}",
            out.status,
            String::from_utf8_lossy(&out.stdout)
        );
        parse_canary_id(&String::from_utf8_lossy(&out.stdout))
    }

    /// Submit a signed `nn-admin canary deploy credential --path <file>
    /// --cred-family <family>`. Returns the canary_id.
    fn deploy_credential_canary(&self, name: &str, decoy_path: &Path, family: &str) -> String {
        let out = Command::new(&self.nn_admin_path)
            .arg("canary")
            .arg("deploy")
            .arg("--name")
            .arg(name)
            .arg("--key")
            .arg(&self.admin_priv)
            .arg("--agent-id-file")
            .arg(&self.agent_id_file)
            .arg("--socket")
            .arg(&self.admin_socket)
            .arg("credential")
            .arg("--path")
            .arg(decoy_path)
            .arg("--cred-family")
            .arg(family)
            .stderr(Stdio::inherit())
            .output()
            .expect("spawn nn-admin canary deploy credential");
        assert!(
            out.status.success(),
            "nn-admin canary deploy credential: exit {:?}, stdout {:?}",
            out.status,
            String::from_utf8_lossy(&out.stdout)
        );
        parse_canary_id(&String::from_utf8_lossy(&out.stdout))
    }

    /// The registry rows of `canary_id`.
    fn registry_rows(&self, canary_id: &str) -> Vec<serde_json::Value> {
        common::read_jsonl_strict(&self.canary_registry)
            .into_iter()
            .filter(|r| r["canary_id"].as_str() == Some(canary_id))
            .collect()
    }

    /// Submit a signed `nn-admin canary deploy process --path
    /// <bin> --fake-arg0 <arg>` op against the running agent.
    /// Returns the freshly-allocated canary_id.
    fn deploy_process_canary(&self, name: &str, exe_path: &Path, fake_arg0: &str) -> String {
        let out = Command::new(&self.nn_admin_path)
            .arg("canary")
            .arg("deploy")
            .arg("--name")
            .arg(name)
            .arg("--key")
            .arg(&self.admin_priv)
            .arg("--agent-id-file")
            .arg(&self.agent_id_file)
            .arg("--socket")
            .arg(&self.admin_socket)
            .arg("process")
            .arg("--path")
            .arg(exe_path)
            .arg("--fake-arg0")
            .arg(fake_arg0)
            .stderr(Stdio::inherit())
            .output()
            .expect("spawn nn-admin canary deploy process");
        assert!(
            out.status.success(),
            "nn-admin canary deploy process: exit {:?}, stdout {:?}",
            out.status,
            String::from_utf8_lossy(&out.stdout)
        );
        parse_canary_id(&String::from_utf8_lossy(&out.stdout))
    }

    /// Lab PR 163: submit a signed `nn-admin canary deploy network
    /// --bind-addr <addr> --bind-port <port>`. Returns the canary_id.
    fn deploy_network_canary(&self, name: &str, bind_addr: &str, bind_port: u16) -> String {
        let out = Command::new(&self.nn_admin_path)
            .arg("canary")
            .arg("deploy")
            .arg("--name")
            .arg(name)
            .arg("--key")
            .arg(&self.admin_priv)
            .arg("--agent-id-file")
            .arg(&self.agent_id_file)
            .arg("--socket")
            .arg(&self.admin_socket)
            .arg("network")
            .arg("--bind-addr")
            .arg(bind_addr)
            .arg("--bind-port")
            .arg(bind_port.to_string())
            .stderr(Stdio::inherit())
            .output()
            .expect("spawn nn-admin canary deploy network");
        assert!(
            out.status.success(),
            "nn-admin canary deploy network: exit {:?}, stdout {:?}",
            out.status,
            String::from_utf8_lossy(&out.stdout)
        );
        parse_canary_id(&String::from_utf8_lossy(&out.stdout))
    }

    /// Submit a signed `nn-admin canary refresh --canary-id <id>`
    /// op against the running agent. Per §7.4 + §12 Q2 this
    /// clears the K2 registry's `tripped` flag so the NEXT
    /// observed access fires again with `first_trip = true`.
    fn refresh(&self, canary_id: &str) {
        let status = Command::new(&self.nn_admin_path)
            .arg("canary")
            .arg("refresh")
            .arg("--canary-id")
            .arg(canary_id)
            .arg("--key")
            .arg(&self.admin_priv)
            .arg("--agent-id-file")
            .arg(&self.agent_id_file)
            .arg("--socket")
            .arg(&self.admin_socket)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .expect("spawn nn-admin canary refresh");
        assert!(
            status.success(),
            "nn-admin canary refresh: exit {status:?} (canary_id={canary_id})"
        );
    }

    /// Lab PR 260: block until the agent exits by itself (a `debug-trigger`
    /// stop); its exit status (sudo's, which waits for it).
    #[cfg(feature = "debug-trigger")]
    fn wait_agent_exit(&mut self, timeout: Duration) -> std::process::ExitStatus {
        let deadline = Instant::now() + timeout;
        let child = self._agent_guard.0.as_mut().expect("the agent was started");
        loop {
            if let Some(status) = child.try_wait().expect("try_wait on the agent") {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "the agent kept running {timeout:?} after the stop it was asked for"
            );
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// Block until `canary_access.jsonl` holds at least `n`
    /// chained rows; return them. Polls at `POLL_INTERVAL` until
    /// `ACCESS_LOG_POLL_TIMEOUT`.
    fn wait_access(&self, n: usize) -> Vec<serde_json::Value> {
        let deadline = Instant::now() + ACCESS_LOG_POLL_TIMEOUT;
        while Instant::now() < deadline {
            let rows = common::read_jsonl_strict(&self.canary_access_log);
            if rows.len() >= n {
                return rows;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        let rows = common::read_jsonl_strict(&self.canary_access_log);
        panic!(
            "canary access log {} held {} rows after {:?} — wanted >= {}; \
             current rows: {:?}",
            self.canary_access_log.display(),
            rows.len(),
            ACCESS_LOG_POLL_TIMEOUT,
            n,
            rows
        );
    }
}

fn parse_canary_id(stdout: &str) -> String {
    // Success line shape: "canary deploy: success (<id>)" (with
    // optional ANSI colour codes when stdout is a TTY; tests
    // pipe stdout so colourisation is disabled).
    for line in stdout.lines() {
        if let Some(rest) = line.trim().strip_prefix("canary deploy: success (") {
            if let Some(id) = rest.strip_suffix(')') {
                return id.to_string();
            }
        }
    }
    panic!("no `canary deploy: success (<id>)` line in nn-admin stdout: {stdout:?}");
}

fn wait_for_socket(path: &Path) {
    let deadline = Instant::now() + SOCKET_POLL_TIMEOUT;
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    panic!(
        "agent never opened admin socket at {} within {:?}",
        path.display(),
        SOCKET_POLL_TIMEOUT
    );
}

// ── Test 1: file canary trip → access-log entry with first_trip ─────

/// K8 e2e #1 — file canary trip. Deploy a file canary at
/// `<tempdir>/decoy_aws_keys.txt`, `cat` it from a subprocess,
/// assert exactly one row in `canary_access.jsonl` with
/// `access_kind = FileOpen`, `canary_type = File`, `first_trip =
/// true`, and `canary_id` matching what `nn-admin canary deploy`
/// reported.
///
/// `cat` lives at `/usr/bin/cat` so the R009_RootExecFromUserPath
/// rule never matches on the subprocess itself (cat is a system
/// binary). The K3 detector's inline-filter precedence intercepts
/// the `inode_file_open` LSM event for the decoy path and emits
/// `Event::CanaryTripped` INSTEAD of `Event::Fim`, so the rule
/// engine routes through NN-L-CANARY-001 rather than any FIM rule.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn file_canary_open_triggers_canary_tripped_event_and_combat() {
    // K5 NN-L-CANARY-001 fires at Critical severity, which the
    // posture FSM translates to Combat → `NetworkIsolator`
    // installs the production NORTHNARROW_COMBAT iptables chain.
    // The test exits without an unlock op, so without the RAII
    // guard the chain would persist and isolate the host (twice
    // observed during K8 verification before this hotfix).
    let _eni = EniIptablesGuard::install();

    // Pre-create the decoy file BEFORE agent spawn so its inode
    // is in WATCHED_PATHS when the kernel `inode_file_open` hook
    // attaches. The agent reads fim-paths.v1 + stat()s each path
    // exactly once at boot — a path that doesn't yet exist gets
    // silently skipped and never traps an open.
    // External audit DEC-001: the decoy is NOT pre-listed in
    // fim-paths.v1 (it used to be, which hid that a deployed decoy was
    // never watched) and does not exist before the deploy, which writes
    // it.
    let tmp = tempfile::tempdir().expect("decoy tempdir");
    let decoy = tmp.path().join("decoy_aws_keys.txt");
    let fx = CanaryFixture::setup(&[]);
    let canary_id = fx.deploy_file_canary("honeypot-aws", &decoy);
    assert_eq!(canary_id.len(), 32, "canary_id should be 32 hex chars");

    // Trip: cat the decoy file from a subprocess. `cat` lives in
    // /usr/bin/cat (a system path), so R009 doesn't fire on the
    // subprocess spawn — the only rule that could match is the
    // K5 NN-L-CANARY-001 we want to test.
    let status = Command::new("cat")
        .arg(&decoy)
        .stdout(Stdio::null())
        .status()
        .expect("spawn cat for canary trip");
    assert!(status.success(), "cat subprocess failed");

    // Wait for the chained access row.
    let rows = fx.wait_access(1);
    assert_eq!(
        rows.len(),
        1,
        "expected exactly one canary access row after first trip; got {rows:?}"
    );
    let row = &rows[0];
    assert_eq!(row["canary_id"].as_str(), Some(canary_id.as_str()));
    assert_eq!(row["canary_name"].as_str(), Some("honeypot-aws"));
    assert_eq!(row["canary_type"].as_str(), Some("File"));
    assert_eq!(row["access_kind"].as_str(), Some("FileOpen"));
    assert_eq!(
        row["first_trip"].as_bool(),
        Some(true),
        "first observed access MUST be marked first_trip=true"
    );
    // Chain integrity smoke: signed row carries non-empty
    // prev_hash, entry_hash, agent_sig per Tappa 8 B1 shape.
    assert!(row["prev_hash"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(
        row["entry_hash"].as_str().unwrap_or("").len(),
        64,
        "entry_hash should be 64 hex chars (SHA-256)"
    );
    // K8.2: `agent_sig` is base64 of the 64-byte Ed25519
    // signature, NOT hex. See `crates/nn-linux/src/canary/access_log.rs`
    // `entry.agent_sig = B64.encode(sig.to_bytes())` and the
    // matching `B64.decode + len==64` check in the verifier
    // (mirrors nn-evidence's `audit` + nn-linux's `fim::baseline`).
    // Standard-padded base64 of 64 bytes is 88 chars, but
    // decode+length-check is the robust shape — it also catches
    // truncated / non-base64 garbage.
    let sig_b64 = row["agent_sig"]
        .as_str()
        .expect("agent_sig field must be present on a sealed row");
    let sig_bytes = B64.decode(sig_b64).expect("agent_sig must be valid base64");
    assert_eq!(
        sig_bytes.len(),
        64,
        "agent_sig must decode to 64 bytes (Ed25519 signature); got {} bytes",
        sig_bytes.len()
    );
}

/// External audit DEC-001 and DEC-003: a file canary deployed at runtime
/// in a directory the FIM path list does not cover trips, and still trips
/// after the agent restarts — the boot used to publish an empty
/// read-forward set and leave the decoy unwatched.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn file_canary_deployed_at_runtime_survives_an_agent_restart() {
    let _eni = EniIptablesGuard::install();
    let tmp = tempfile::tempdir().expect("decoy tempdir");
    let decoy = tmp.path().join("payroll").join("2026_salaries.xlsx");
    let mut fx = CanaryFixture::setup(&[]);
    let canary_id = fx.deploy_file_canary("honeypot-payroll", &decoy);

    let cat = || {
        Command::new("cat")
            .arg(&decoy)
            .stdout(Stdio::null())
            .status()
            .expect("spawn cat for canary trip")
    };
    assert!(cat().success());
    let rows = fx.wait_access(1);
    assert_eq!(rows[0]["canary_id"].as_str(), Some(canary_id.as_str()));

    fx.restart();
    std::thread::sleep(Duration::from_millis(500));
    assert!(cat().success());
    let rows = fx.wait_access(2);
    assert_eq!(
        rows[1]["canary_id"].as_str(),
        Some(canary_id.as_str()),
        "a read after the restart must trip the canary again: {rows:?}"
    );
    // External audit DEC-011: the canary was tripped before the restart
    // and still is: the read after it is recorded, not responded to again
    // (the state used to live in memory only).
    assert_eq!(
        rows[1]["first_trip"].as_bool(),
        Some(false),
        "a canary tripped before the restart is not a first trip after it: {rows:?}"
    );
    let trips: Vec<_> = fx
        .registry_rows(&canary_id)
        .into_iter()
        .filter(|r| r["action"].as_str() == Some("trip"))
        .collect();
    assert_eq!(trips.len(), 1, "one Trip row: {trips:?}");
    assert_eq!(
        trips[0]["first_trip_access_hash"].as_str(),
        rows[0]["entry_hash"].as_str(),
        "the Trip row names the access row of the first trip"
    );
}

/// Lab PR 260: the agent stopped between a trip's access row and the
/// registry's `Trip` row — where lab PR 258's KVM run saw the restart's
/// SIGQUIT land in the test above, which then found the canary armed again
/// — keeps the trip. The next start finds the access row, records the trip
/// (a signed `canary_trip_recovered`, then a `Trip` row naming that row),
/// and the next read is recorded, not a first trip; the start after finds
/// nothing more to record. The stop is the `debug-trigger` failpoint: a
/// file `debug-canary-stop-before-trip` next to the registry, and the agent
/// aborts at the detector's trip mark, after the access row. On the
/// starting code the canary came back armed and the next read was a first
/// trip.
#[cfg(feature = "debug-trigger")]
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn a_trip_the_agent_stopped_before_recording_is_kept_across_the_restart() {
    let _eni = EniIptablesGuard::install();
    let tmp = tempfile::tempdir().expect("decoy tempdir");
    let decoy = tmp.path().join("finance").join("q3_forecast.xlsx");
    let mut fx = CanaryFixture::setup(&[]);
    let canary_id = fx.deploy_file_canary("honeypot-forecast", &decoy);
    let trigger = fx
        .canary_registry
        .with_file_name("debug-canary-stop-before-trip");
    std::fs::write(&trigger, b"").expect("write the stop trigger");

    let cat = || {
        Command::new("cat")
            .arg(&decoy)
            .stdout(Stdio::null())
            .status()
            .expect("spawn cat for canary trip")
    };
    assert!(cat().success());
    let rows = fx.wait_access(1);
    assert_eq!(rows[0]["canary_id"].as_str(), Some(canary_id.as_str()));
    assert_eq!(rows[0]["first_trip"].as_bool(), Some(true), "{rows:?}");
    let status = fx.wait_agent_exit(ACCESS_LOG_POLL_TIMEOUT);
    assert!(!status.success(), "the agent aborted: {status}");
    assert!(!trigger.exists(), "the agent took the trigger");
    let trips = |fx: &CanaryFixture| -> Vec<serde_json::Value> {
        fx.registry_rows(&canary_id)
            .into_iter()
            .filter(|r| r["action"].as_str() == Some("trip"))
            .collect()
    };
    let recovered = |fx: &CanaryFixture| -> Vec<serde_json::Value> {
        common::read_jsonl_strict(&fx.audit_log)
            .into_iter()
            .filter(|r| r["op"].as_str() == Some("canary_trip_recovered"))
            .collect()
    };
    assert!(
        trips(&fx).is_empty(),
        "stopped before the registry's Trip row: {:?}",
        fx.registry_rows(&canary_id)
    );

    fx.stop();
    fx.start();
    let recorded = trips(&fx);
    assert_eq!(
        recorded.len(),
        1,
        "the start recorded the trip: {recorded:?}"
    );
    assert_eq!(
        recorded[0]["first_trip_access_hash"].as_str(),
        rows[0]["entry_hash"].as_str(),
        "the Trip row names the access row"
    );
    let audit = recovered(&fx);
    assert_eq!(
        audit.len(),
        1,
        "one signed canary_trip_recovered: {audit:?}"
    );
    assert_eq!(
        audit[0]["extra"]["canary_id"].as_str(),
        Some(canary_id.as_str())
    );
    assert_eq!(
        audit[0]["extra"]["access_entry_hash"].as_str(),
        rows[0]["entry_hash"].as_str()
    );
    assert_eq!(audit[0]["extra"]["first_trip_rows"].as_u64(), Some(1));

    std::thread::sleep(Duration::from_millis(500));
    assert!(cat().success());
    let rows = fx.wait_access(2);
    assert_eq!(rows[1]["canary_id"].as_str(), Some(canary_id.as_str()));
    assert_eq!(
        rows[1]["first_trip"].as_bool(),
        Some(false),
        "the canary stayed tripped across the restart: {rows:?}"
    );

    fx.restart();
    assert_eq!(trips(&fx).len(), 1, "recorded once");
    assert_eq!(recovered(&fx).len(), 1, "attested once");
}

/// External audit DEC-010: a decoy changed while the agent is down is
/// reported when it starts — an ERROR, a signed `integrity_drift`
/// (`canary_decoy_tampered`) and a `decoy_check` row the registry (`canary
/// list`) shows. The boot used to re-arm whatever was at the path. Also
/// DEC-007: the credential decoy names nothing.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn a_decoy_changed_while_the_agent_is_down_is_reported() {
    let _eni = EniIptablesGuard::install();
    let tmp = tempfile::tempdir().expect("decoy tempdir");
    let decoy = tmp.path().join(".aws").join("credentials");
    let mut fx = CanaryFixture::setup(&[]);
    let canary_id = fx.deploy_credential_canary("aws-backup", &decoy, "aws");
    let deployed = fx.registry_rows(&canary_id);
    let sha = deployed[0]["contents_sha256"]
        .as_str()
        .expect("the deploy row records the decoy's SHA-256")
        .to_string();

    fx.stop();
    // Read and changed by other processes, with the agent down.
    let out = Command::new("cat").arg(&decoy).output().expect("spawn cat");
    let body = String::from_utf8_lossy(&out.stdout).to_lowercase();
    assert!(body.contains("aws_access_key_id"), "{body}");
    for m in ["northnarrow", "canary", "do not use", "decoy", "nn-l-"] {
        assert!(!body.contains(m), "the decoy carries {m:?}: {body}");
    }
    let status = Command::new("sh")
        .arg("-c")
        .arg("printf '[default]\\n' > \"$1\"")
        .arg("sh")
        .arg(&decoy)
        .status()
        .expect("spawn sh");
    assert!(status.success());
    fx.start();

    let deadline = Instant::now() + ACCESS_LOG_POLL_TIMEOUT;
    let audit = loop {
        let found: Vec<_> = common::read_jsonl_strict(&fx.audit_log)
            .into_iter()
            .filter(|r| r["op"].as_str() == Some("integrity_drift"))
            .filter(|r| r["extra"]["kind"].as_str() == Some("canary_decoy_tampered"))
            .collect();
        if !found.is_empty() || Instant::now() > deadline {
            break found;
        }
        std::thread::sleep(POLL_INTERVAL);
    };
    assert_eq!(audit.len(), 1, "one signed integrity_drift: {audit:?}");
    assert_eq!(
        audit[0]["extra"]["canary_id"].as_str(),
        Some(canary_id.as_str())
    );
    assert_eq!(audit[0]["extra"]["state"].as_str(), Some("modified"));
    assert_eq!(
        audit[0]["extra"]["expected_sha256"].as_str(),
        Some(sha.as_str())
    );
    let checks: Vec<_> = fx
        .registry_rows(&canary_id)
        .into_iter()
        .filter(|r| r["action"].as_str() == Some("decoy_check"))
        .collect();
    assert_eq!(checks.len(), 1, "{checks:?}");
    assert_eq!(checks[0]["decoy_state"].as_str(), Some("modified"));

    // Recorded once: a second start finds what is recorded.
    fx.restart();
    std::thread::sleep(Duration::from_secs(2));
    let n = fx
        .registry_rows(&canary_id)
        .iter()
        .filter(|r| r["action"].as_str() == Some("decoy_check"))
        .count();
    assert_eq!(n, 1, "the same state is not recorded again");
}

/// External audit DEC-008: each deploy and each refresh writes a credential
/// of its own (the seed was the operator's fingerprint and the path, the
/// same on every host), recorded in the registry; the bytes on disk are
/// the ones recorded.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn credential_decoys_are_new_at_each_deploy_and_refresh() {
    use sha2::{Digest, Sha256};
    let _eni = EniIptablesGuard::install();
    let tmp = tempfile::tempdir().expect("decoy tempdir");
    let decoy = tmp.path().join("gcp-sa.json");
    let mut fx = CanaryFixture::setup(&[]);
    let first = fx.deploy_credential_canary("gcp-a", &decoy, "gcp");
    let a = fx.registry_rows(&first)[0].clone();
    // the same operator, the same path
    let second = fx.deploy_credential_canary("gcp-b", &decoy, "gcp");
    let b = fx.registry_rows(&second)[0].clone();
    assert_ne!(a["contents_sha256"], b["contents_sha256"]);
    assert_ne!(a["content_seed"], b["content_seed"]);
    fx.refresh(&second);
    let rows = fx.registry_rows(&second);
    let refreshed = rows
        .iter()
        .find(|r| r["action"].as_str() == Some("refresh"))
        .expect("refresh row");
    assert_ne!(refreshed["contents_sha256"], b["contents_sha256"]);
    assert_eq!(refreshed["decoy_state"].as_str(), Some("intact"));

    fx.stop();
    let out = Command::new("cat").arg(&decoy).output().expect("spawn cat");
    assert_eq!(
        Some(hex::encode(Sha256::digest(&out.stdout)).as_str()),
        refreshed["contents_sha256"].as_str(),
        "the decoy on disk is the one the refresh recorded"
    );
    let body = String::from_utf8_lossy(&out.stdout).to_lowercase();
    for m in ["northnarrow", "canary", "nn-l-"] {
        assert!(!body.contains(m), "the decoy carries {m:?}");
    }
}

// ── Test 2: process canary trip → access-log entry with first_trip ──

/// K8 e2e #2 — process canary trip. Materialise a fake binary
/// at `<tempdir>/decoy_helper` (copy of /bin/true so the exec
/// returns 0), deploy a process canary at that path, then
/// `exec`-spawn the path. Assert exactly one row with
/// `access_kind = ProcessExec`, `canary_type = Process`,
/// `first_trip = true`.
///
/// Why the K3 inline-filter wins over R009: the kernel surfaces
/// `Event::ProcessSpawn { filename = /tmp/.../decoy_helper, uid=0 }`,
/// which BOTH (a) the K3 detector's `is_canary_exe` lookup
/// matches AND (b) R009's `/tmp/`-prefix matcher would match.
/// Per §12 Q9 INLINE-FILTER lock-in: the detector runs FIRST in
/// `main::process_event` and REPLACES the source event with
/// `Event::CanaryTripped`. The rule engine then routes through
/// NN-L-CANARY-002 (canary rule) and never sees the original
/// ProcessSpawn that R009 would have matched on.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn process_canary_exec_triggers_canary_tripped_event_and_combat() {
    // K5 NN-L-CANARY-002 → Combat → iptables chain. RAII cleanup
    // restores the host's network on test exit (pass / fail /
    // panic).
    let _eni = EniIptablesGuard::install();

    // Process canary path can be created post-spawn — sched_process_exec
    // is a tracepoint, not a WATCHED_PATHS-gated LSM hook; the K3
    // detector matches via the registry's exe_index after deploy.
    let tmp = tempfile::tempdir().expect("decoy tempdir");
    let decoy = tmp.path().join("decoy_helper");
    // Real ELF at the deployment path so the exec doesn't ENOENT.
    // /bin/true is the smallest exec-and-return-0 binary on
    // every distribution we target.
    std::fs::copy("/bin/true", &decoy).expect("seed decoy process binary");
    let mut perms = std::fs::metadata(&decoy).expect("stat decoy").permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o755);
    std::fs::set_permissions(&decoy, perms).expect("chmod decoy");

    let fx = CanaryFixture::setup(&[]);
    let canary_id = fx.deploy_process_canary("honeypot-helper", &decoy, "helper");
    assert_eq!(canary_id.len(), 32);

    // Trip: exec the canary binary.
    let status = Command::new(&decoy)
        .stdout(Stdio::null())
        .status()
        .expect("spawn decoy process for canary trip");
    assert!(status.success(), "decoy exec failed");

    let rows = fx.wait_access(1);
    assert_eq!(
        rows.len(),
        1,
        "expected exactly one canary access row after first trip; got {rows:?}"
    );
    let row = &rows[0];
    assert_eq!(row["canary_id"].as_str(), Some(canary_id.as_str()));
    assert_eq!(row["canary_name"].as_str(), Some("honeypot-helper"));
    assert_eq!(row["canary_type"].as_str(), Some("Process"));
    assert_eq!(row["access_kind"].as_str(), Some("ProcessExec"));
    assert_eq!(
        row["first_trip"].as_bool(),
        Some(true),
        "first observed exec MUST be marked first_trip=true"
    );
    // The exec is uid=0 (we run under sudo), captured on the row.
    assert_eq!(row["accessor_uid"].as_u64(), Some(0));
    // Process-canary trips capture the accessor's comm — the
    // kernel-side `sched_process_exec` populates this from the
    // task struct. Don't pin the value (comm may be "decoy_helper"
    // or "true" depending on how the kernel resolves it) — just
    // assert it's a non-empty string.
    assert!(
        row["accessor_comm"].as_str().is_some_and(|s| !s.is_empty()),
        "accessor_comm should be populated"
    );
}

// ── Test 3: refresh re-arms a tripped canary for repeat trips ───────

/// K8 e2e #3 — refresh re-arms a tripped canary. Per §12 Q2
/// MANUAL REFRESH + K2 `Registry::refresh`: once a canary has
/// been tripped, the `tripped` flag stays set + subsequent
/// accesses log with `first_trip = false` (so the K5 rule
/// abstains, preserving the original §12 Q2 single-trip
/// posture-transition contract). Calling `nn-admin canary
/// refresh <id>` clears the flag, and the NEXT observed access
/// fires fresh as `first_trip = true`.
///
/// This test pins the round-trip:
/// 1. Deploy file canary, trip once → row 1 with first_trip=true
/// 2. Refresh via signed admin op
/// 3. Trip again → row 2 with first_trip=true (NOT false — the
///    K3 detector's `mark_tripped` returns true again because
///    refresh reset the in-memory tripped flag)
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn refresh_rearms_canary_for_repeat_trips() {
    // Two K5 Critical trips during this test → Combat engages
    // twice. RAII cleanup restores the host's network on exit.
    let _eni = EniIptablesGuard::install();

    let tmp = tempfile::tempdir().expect("decoy tempdir");
    let decoy = tmp.path().join("decoy_rearm.txt");
    let fx = CanaryFixture::setup(&[]);

    let canary_id = fx.deploy_file_canary("honeypot-rearm", &decoy);

    // First trip.
    let _ = Command::new("cat")
        .arg(&decoy)
        .stdout(Stdio::null())
        .status()
        .expect("spawn cat (trip #1)");
    let rows = fx.wait_access(1);
    assert_eq!(
        rows[0]["first_trip"].as_bool(),
        Some(true),
        "trip #1 must be first_trip=true"
    );

    // Refresh — signed admin op, clears the tripped flag.
    fx.refresh(&canary_id);

    // Second trip. Give the kernel a moment to settle so the
    // open is observed AFTER the refresh propagated.
    std::thread::sleep(Duration::from_millis(200));
    let _ = Command::new("cat")
        .arg(&decoy)
        .stdout(Stdio::null())
        .status()
        .expect("spawn cat (trip #2)");
    let rows = fx.wait_access(2);
    // Row 2 must also be first_trip=true because refresh
    // re-armed the canary. Without refresh, the K2 contract
    // would put first_trip=false on this row.
    assert_eq!(
        rows[1]["first_trip"].as_bool(),
        Some(true),
        "post-refresh trip MUST fire as first_trip=true again (§7.4 re-arm); \
         got row {row:?}",
        row = rows[1]
    );
    assert_eq!(rows[1]["canary_id"].as_str(), Some(canary_id.as_str()));
}

// ── Test 4: network canary connect → access row, verdict, kill ─────

/// A loopback port nothing listens on: bound, then released.
fn unused_loopback_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    l.local_addr().expect("local addr").port()
}

/// A shell that connects to `addr:port` (bash's `/dev/tcp`; the connect
/// is the shell's own, the redirection of a builtin), then waits
/// `then_sleep` seconds. Returns the child.
fn connect_from_a_shell(addr: &str, port: u16, then_sleep: u32) -> Child {
    Command::new("/bin/bash")
        .arg("-c")
        .arg(format!(
            "echo > /dev/tcp/{addr}/{port}; sleep {then_sleep}; exit 0"
        ))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn bash for the network canary connect")
}

/// How `child` ended, waited for at most `timeout`; `None` if it still
/// runs (then killed).
fn wait_exit(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return Some(status);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

/// Lab PR 163 (NN-L-CANARY-003 could not fire: nothing produced a Network
/// canary trip). A network canary is a decoy destination: a local process
/// connecting to its address and port trips it (`canary::network`; the
/// agent opens no listener, the connect kprobe names the process). Here
/// the destination is a loopback port nothing listens on.
///
/// - a connect to another port first trips nothing (events are handled in
///   order: a row for it would precede the trip's);
/// - the trip: one signed access row (`NetworkConnect`, `first_trip`, the
///   shell as the accessor), the registry's `trip` row naming it, the
///   NN-L-CANARY-003 record (Critical, KillProcessTree) and the shell
///   killed (SIGKILL) during its sleep;
/// - a second connect is recorded with `first_trip = false` and, as every
///   connect to a network canary (external audit NETR-006), killed;
/// - the close of a trip's connection is not judged again: no
///   NN-L-CHAIN-003 record (checked after an exec barrier). Lab PR 246:
///   whichever ring the agent reads first — the KVM run of 27/10/2026 had
///   the close synthesised by the flow tracker (`127.0.0.1:0`, the refused
///   connect's port cleared) and judged after the trip as an egress.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn network_canary_connect_trips_canary_003_and_kills_the_connector() {
    use std::os::unix::process::ExitStatusExt;
    // NN-L-CANARY-003 is Critical; the guard restores the host's network
    // whatever the posture does.
    let _eni = EniIptablesGuard::install();
    let fx = CanaryFixture::setup(&[]);
    let port = unused_loopback_port();
    let mut other = unused_loopback_port();
    while other == port {
        other = unused_loopback_port();
    }
    let canary_id = fx.deploy_network_canary("decoy-db", "127.0.0.1", port);
    assert_eq!(canary_id.len(), 32);
    std::thread::sleep(Duration::from_millis(200));

    // Not the canary's port: refused, the shell exits 0 on its own.
    let mut miss = connect_from_a_shell("127.0.0.1", other, 0);
    let miss_pid = u64::from(miss.id());
    let status = wait_exit(&mut miss, Duration::from_secs(10)).expect("the miss shell exits");
    assert!(status.success(), "a connect to another port: {status:?}");

    // The trip.
    let mut shell = connect_from_a_shell("127.0.0.1", port, 30);
    let shell_pid = u64::from(shell.id());
    let rows = fx.wait_access(1);
    let row = &rows[0];
    assert_ne!(
        row["accessor_pid"].as_u64(),
        Some(miss_pid),
        "a connect to another port tripped the canary: {rows:?}"
    );
    assert_eq!(row["canary_id"].as_str(), Some(canary_id.as_str()));
    assert_eq!(row["canary_type"].as_str(), Some("Network"));
    assert_eq!(row["access_kind"].as_str(), Some("NetworkConnect"));
    assert_eq!(row["accessor_pid"].as_u64(), Some(shell_pid), "{row}");
    assert_eq!(row["first_trip"].as_bool(), Some(true), "{row}");
    assert_eq!(row["entry_hash"].as_str().unwrap_or("").len(), 64);

    let rec = common::wait_jsonl_row(
        &fx.detections_log,
        ACCESS_LOG_POLL_TIMEOUT,
        "NN-L-CANARY-003 record of the shell",
        |r| {
            r["rule_id"].as_str() == Some("NN-L-CANARY-003_NetworkConnect")
                && r["principal"]["pid"].as_u64() == Some(shell_pid)
        },
    );
    assert_eq!(rec["severity"], "Critical", "record: {rec}");
    assert!(
        rec["response"]
            .as_str()
            .is_some_and(|r| r.starts_with("KillProcessTree")),
        "record: {rec}"
    );
    let status = wait_exit(&mut shell, Duration::from_secs(10))
        .expect("the connecting shell must be killed during its 30 s sleep");
    assert_eq!(status.signal(), Some(9), "{status:?}");

    let trips: Vec<_> = fx
        .registry_rows(&canary_id)
        .into_iter()
        .filter(|r| r["action"].as_str() == Some("trip"))
        .collect();
    assert_eq!(trips.len(), 1, "one Trip row: {trips:?}");
    assert_eq!(
        trips[0]["first_trip_access_hash"].as_str(),
        row["entry_hash"].as_str(),
        "the Trip row names the access row of the first trip"
    );

    // A second connect: recorded, not a first trip; killed all the same.
    let mut second = connect_from_a_shell("127.0.0.1", port, 30);
    let second_pid = u64::from(second.id());
    let rows = fx.wait_access(2);
    assert_eq!(rows[1]["accessor_pid"].as_u64(), Some(second_pid));
    assert_eq!(rows[1]["first_trip"].as_bool(), Some(false), "{rows:?}");
    let status = wait_exit(&mut second, Duration::from_secs(10)).expect("killed");
    assert_eq!(status.signal(), Some(9), "{status:?}");

    // The closes of the trips' connections are not judged again.
    common::exec_barrier(&fx.detections_log, ACCESS_LOG_POLL_TIMEOUT);
    let chain: Vec<_> = common::records_of(&fx.detections_log, "NN-L-CHAIN-003_CanaryThenEgress")
        .into_iter()
        .filter(|r| {
            let pid = r["principal"]["pid"].as_u64();
            pid == Some(shell_pid) || pid == Some(second_pid)
        })
        .collect();
    assert!(
        chain.is_empty(),
        "the trip's own connection drew NN-L-CHAIN-003: {chain:?}"
    );
    assert_eq!(
        common::read_jsonl_strict(&fx.canary_access_log).len(),
        2,
        "one row per connect to the canary"
    );
}
