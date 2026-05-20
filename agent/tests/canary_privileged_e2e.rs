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
//!   §12 Q2 + §7.4 MANUAL-REFRESH contract).
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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SOCKET_POLL_TIMEOUT: Duration = Duration::from_secs(15);
const ACCESS_LOG_POLL_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

fn agent_bin() -> &'static str {
    env!("CARGO_BIN_EXE_northnarrow-agent")
}

fn nn_admin_bin() -> &'static str {
    env!("CARGO_BIN_EXE_nn-admin")
}

fn combat_rules_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("configs")
        .join("combat-rules.v4")
}

fn canary_templates_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("configs")
        .join("canary-templates")
}

/// SIGQUIT-on-drop guard (Tappa 7 LSM blocks SIGKILL + SIGTERM from
/// userland; SIGQUIT is the documented shutdown signal).
struct AgentGuard(Option<Child>);

impl Drop for AgentGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            unsafe {
                libc::kill(c.id() as i32, libc::SIGQUIT);
            }
            let _ = c.wait();
        }
    }
}

/// K8.1 R009 avoidance: sudo-install agent + nn-admin under
/// `/usr/local/bin/<basename>-e2etest-<ts>-<pid>` so the
/// post-spawn nn-admin canary deploy / refresh calls don't
/// trip the agent's `R009_RootExecFromUserPath` rule (which
/// kills any root spawn originating from `/home/`, `/tmp/`,
/// `/var/tmp/`). Ported verbatim from
/// `agent/tests/privileged_e2e.rs` PHASE_D_003 / commit 18baa66
/// (and originally from `watchdog/tests/privileged_e2e.rs`
/// PHASE_D_001 W8). Same pattern, same RAII cleanup.
const PRIV_BIN_DIR: &str = "/usr/local/bin";

struct InstalledBin {
    path: PathBuf,
}
impl Drop for InstalledBin {
    fn drop(&mut self) {
        let _ = Command::new("sudo")
            .arg("rm")
            .arg("-f")
            .arg(&self.path)
            .status();
    }
}

fn install_to_priv_bin(src: &Path) -> InstalledBin {
    let basename = src
        .file_name()
        .and_then(|s| s.to_str())
        .expect("binary path has a UTF-8 basename");
    let ts_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let dst = PathBuf::from(format!("{PRIV_BIN_DIR}/{basename}-e2etest-{ts_ns}-{pid}"));
    let status = Command::new("sudo")
        .arg("install")
        .arg("-m")
        .arg("755")
        .arg("-o")
        .arg("root")
        .arg("-g")
        .arg("root")
        .arg(src)
        .arg(&dst)
        .status()
        .expect("spawn sudo install");
    assert!(
        status.success(),
        "sudo install of {} to {} failed",
        src.display(),
        dst.display()
    );
    InstalledBin { path: dst }
}

fn install_priv_bins() -> (InstalledBin, InstalledBin) {
    let installed_agent = install_to_priv_bin(Path::new(agent_bin()));
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
    /// K8.1 R009 avoidance: the `/usr/local/bin/` installed
    /// nn-admin path. Every nn-admin subprocess spawn (deploy,
    /// refresh, init) routes through this path so R009 doesn't
    /// kill the op mid-flight. Kept alive by `_installed_admin`.
    nn_admin_path: PathBuf,
    /// Drop order: AgentGuard first (SIGQUIT the agent), then
    /// the InstalledBin handles (sudo rm the /usr/local/bin/
    /// copies). Rust drops struct fields in declaration order,
    /// so keep `_agent_guard` BEFORE the installed-bin RAII
    /// handles so the agent is gone before we yank its binary.
    _agent_guard: AgentGuard,
    _installed_agent: InstalledBin,
    _installed_admin: InstalledBin,
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
        let admin_pub = dir.join("admin.pub");
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
            let mut f = std::fs::File::create(&fim_paths_v1)
                .expect("create fim-paths.v1");
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

        let audit_log = dir.join("audit.log");
        let signing_key = dir.join("agent.sig.key");
        let agent_id = dir.join("agent_id");
        let admin_socket = dir.join("admin.sock");
        let marker = dir.join("agent.shutdown_authorised");
        let baseline_log = dir.join("fim_baseline.jsonl");
        let drift_log = dir.join("fim_drift.jsonl");
        let canary_registry = dir.join("canaries.jsonl");
        let canary_access = dir.join("canary_access.jsonl");

        // K8.1 R009 avoidance: spawn the installed /usr/local/bin/
        // agent via sudo. Mirrors `agent/tests/privileged_e2e.rs`
        // `spawn_agent_b5_with_installs`; sudo is a no-op when the
        // test process is already root (the runbook's `sudo -E
        // cargo test` invocation) but lets the test work under any
        // privilege-elevation flow that authorises sudo for the
        // user.
        let child = Command::new("sudo")
            .arg(&installed_agent.path)
            .arg("--combat-rules")
            .arg(&combat)
            .arg("--admin-pub")
            .arg(&admin_pub)
            .arg("--admin-socket")
            .arg(&admin_socket)
            .arg("--agent-id-file")
            .arg(&agent_id)
            .arg("--audit-log-file")
            .arg(&audit_log)
            .arg("--signing-key-file")
            .arg(&signing_key)
            .arg("--shutdown-marker-file")
            .arg(&marker)
            .arg("--fim-paths-v1")
            .arg(&fim_paths_v1)
            .arg("--fim-paths-local")
            .arg(&fim_paths_local)
            .arg("--fim-baseline-file")
            .arg(&baseline_log)
            .arg("--fim-drift-file")
            .arg(&drift_log)
            .arg("--canary-registry-file")
            .arg(&canary_registry)
            .arg("--canary-access-file")
            .arg(&canary_access)
            .arg("--canary-template-dir")
            .arg(&templates_dir)
            .arg("--no-ade")
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
            nn_admin_path,
            _agent_guard: guard,
            _installed_agent: installed_agent,
            _installed_admin: installed_admin,
        }
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

    /// Block until `canary_access.jsonl` holds at least `n`
    /// chained rows; return them. Polls at `POLL_INTERVAL` until
    /// `ACCESS_LOG_POLL_TIMEOUT`.
    fn wait_access(&self, n: usize) -> Vec<serde_json::Value> {
        let deadline = Instant::now() + ACCESS_LOG_POLL_TIMEOUT;
        while Instant::now() < deadline {
            let rows = read_jsonl(&self.canary_access_log);
            if rows.len() >= n {
                return rows;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        let rows = read_jsonl(&self.canary_access_log);
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
    panic!(
        "no `canary deploy: success (<id>)` line in nn-admin stdout: {stdout:?}"
    );
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

fn read_jsonl(path: &Path) -> Vec<serde_json::Value> {
    let body = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    body.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
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
    // Pre-create the decoy file BEFORE agent spawn so its inode
    // is in WATCHED_PATHS when the kernel `inode_file_open` hook
    // attaches. The agent reads fim-paths.v1 + stat()s each path
    // exactly once at boot — a path that doesn't yet exist gets
    // silently skipped and never traps an open.
    let tmp = tempfile::tempdir().expect("decoy tempdir");
    let decoy = tmp.path().join("decoy_aws_keys.txt");
    std::fs::write(&decoy, b"placeholder\n").expect("seed decoy file");
    let fx = CanaryFixture::setup(&[&decoy]);
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
    // signature, NOT hex. See `agent/src/canary/access_log.rs`
    // `entry.agent_sig = B64.encode(sig.to_bytes())` and the
    // matching `B64.decode + len==64` check in the verifier
    // (mirrors `agent/src/audit.rs` + `agent/src/fim/baseline.rs`).
    // Standard-padded base64 of 64 bytes is 88 chars, but
    // decode+length-check is the robust shape — it also catches
    // truncated / non-base64 garbage.
    let sig_b64 = row["agent_sig"]
        .as_str()
        .expect("agent_sig field must be present on a sealed row");
    let sig_bytes = B64
        .decode(sig_b64)
        .expect("agent_sig must be valid base64");
    assert_eq!(
        sig_bytes.len(),
        64,
        "agent_sig must decode to 64 bytes (Ed25519 signature); got {} bytes",
        sig_bytes.len()
    );
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
    let tmp = tempfile::tempdir().expect("decoy tempdir");
    let decoy = tmp.path().join("decoy_rearm.txt");
    std::fs::write(&decoy, b"placeholder\n").expect("seed decoy file");
    let fx = CanaryFixture::setup(&[&decoy]);

    let canary_id = fx.deploy_file_canary("honeypot-rearm", &decoy);

    // First trip.
    let _ = Command::new("cat")
        .arg(&decoy)
        .stdout(Stdio::null())
        .status()
        .expect("spawn cat (trip #1)");
    let rows = fx.wait_access(1);
    assert_eq!(rows[0]["first_trip"].as_bool(), Some(true), "trip #1 must be first_trip=true");

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
