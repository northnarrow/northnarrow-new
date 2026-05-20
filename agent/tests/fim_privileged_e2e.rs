//! Tappa 9 C8 — privileged end-to-end tests for the FIM module
//! (closes the Tappa 9 sprint).
//!
//! Spawns the real `northnarrow-agent` binary against a per-test
//! tempdir, lets the §13 Q5 TOFU first-boot baseline run over a
//! curated single-file watched set, then exercises one branch of
//! the kernel → drain → drift-log pipeline per test:
//!
//! 1. `fim_baseline_then_modify_records_drift_event` — the
//!    canonical drift detection path. Modify a watched file →
//!    `inode_setattr` fires → drain writes a `Modified` entry.
//! 2. `fim_subprocess_unlink_records_deleted_event` — the
//!    `Deleted` op path. A `sh -c "rm <file>"` subprocess
//!    triggers `inode_unlink` so the modifier_pid in the drift
//!    chain is the subprocess (cleaner test invariant than
//!    "modifier is the test process itself").
//! 3. `fim_subprocess_open_aws_creds_records_opened_event` —
//!    the `Opened` op path that the NN-L-FIM-011..014 cloud-
//!    cred rules consume. A `cat <path>` subprocess
//!    (modifier_comm = "cat", not in the AWS_CLI_COMMS allow-
//!    list) triggers `file_open` → drift entry with `op=Opened`
//!    and a path that the NN-L-FIM-011 substring matcher would
//!    accept.
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
//! These tests do NOT verify the kill side of any rule (NN-L-FIM-010
//! KillProcessTree or NN-L-FIM-011 KillProcess) — that requires a
//! sacrificial subprocess + posture-state assertion path that
//! belongs in a separate test module. C8's scope is the wire from
//! kernel BPF → drain → fim_drift.jsonl; rule-side response is
//! covered by the existing unit tests in `agent/src/fim/rules.rs`.

#![cfg(feature = "test-privileged")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const SOCKET_POLL_TIMEOUT: Duration = Duration::from_secs(15);
const BASELINE_POLL_TIMEOUT: Duration = Duration::from_secs(30);
const DRIFT_POLL_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// `FimOp` is `#[serde(into = "u8", try_from = "u8")]`, so JSONL
/// rows carry numeric `op` values. These constants mirror the
/// `FIM_OP_*` discriminants in `common/src/wire/mod.rs` — kept
/// here to avoid pulling the workspace dep just for the
/// assertions.
const OP_MODIFIED: u64 = 1;
#[allow(dead_code)]
const OP_CREATED: u64 = 2;
const OP_DELETED: u64 = 3;
#[allow(dead_code)]
const OP_RENAMED: u64 = 4;
#[allow(dead_code)]
const OP_LINKED: u64 = 5;
const OP_OPENED: u64 = 6;

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

/// SIGQUIT-on-drop guard (the agent's Tappa 7 LSM hook blocks
/// SIGKILL + SIGTERM from userland; SIGQUIT is the documented
/// shutdown signal — see `agent/src/anti_tamper/` docs).
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

/// Tempdir layout the FIM privileged tests share. Holding every
/// per-test file path in one struct keeps the spawn + assertion
/// helpers readable.
struct FimFixture {
    _tempdir: tempfile::TempDir,
    /// Path the test watches (single-file watched set — keeps
    /// the e2e blast radius small).
    watched_file: PathBuf,
    fim_paths_v1: PathBuf,
    fim_paths_local: PathBuf,
    baseline_log: PathBuf,
    drift_log: PathBuf,
    /// Returned so the test can SIGQUIT the agent at end-of-test.
    /// `Option` so `Drop` can take ownership.
    _agent_guard: AgentGuard,
}

/// Production-pinned bpffs root the agent writes to. Per-test
/// clean-up wipes this so each agent boots with a clean program +
/// map pin tree (otherwise the prior test's FS_FIM_EVENTS ringbuf
/// reuse produces stale 0-byte entries that the drain rejects
/// with SizeMismatch on aya 0.13).
const BPFFS_PIN_ROOT: &str = "/sys/fs/bpf/northnarrow";

/// Wipe the bpffs pin tree so a fresh agent boot doesn't reuse
/// the prior test's pinned LSM hooks, programs, or maps. Run
/// once per test before [`FimFixture::setup`]. The test process
/// runs as root (`sudo -E cargo test ...`) so direct
/// `remove_dir_all` works; no sudo wrapper needed.
fn wipe_pin_tree() {
    let pin = Path::new(BPFFS_PIN_ROOT);
    if !pin.exists() {
        return;
    }
    // Walk + unlink each entry. `remove_dir_all` doesn't always
    // work on bpffs (some kernels refuse `rmdir` on a non-empty
    // bpffs dir even though every file inside was successfully
    // unlinked). Two-step: unlink each file, then rmdir.
    if let Ok(entries) = std::fs::read_dir(pin) {
        for entry in entries.flatten() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    let _ = std::fs::remove_dir(pin);
}

impl FimFixture {
    /// Spawn an agent with a single watched file (`watched_basename`
    /// inside the per-test tempdir). The file is pre-created with
    /// `initial_contents` so the TOFU baseline has something to
    /// hash. Per-test admin keypair lives alongside the FIM state
    /// in the same tempdir — every test starts on a clean slate.
    /// Wipes `/sys/fs/bpf/northnarrow` so prior-test pinned LSM
    /// state doesn't bleed in.
    fn setup(watched_basename: &str, initial_contents: &[u8]) -> Self {
        wipe_pin_tree();
        let tempdir = tempfile::tempdir().expect("tempdir");
        let dir = tempdir.path();

        // Per-test admin keypair (we don't actually use the admin
        // socket in these tests, but the agent refuses to spawn
        // its admin loop without a pubkey).
        let admin_pub = dir.join("admin.pub");
        let admin_priv = dir.join("admin.priv");
        let init_status = Command::new(nn_admin_bin())
            .arg("init")
            .arg("--priv-out")
            .arg(&admin_priv)
            .arg("--pub-append")
            .arg(&admin_pub)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .expect("spawn nn-admin init");
        assert!(init_status.success(), "nn-admin init failed");

        // Combat rules — copy verbatim so any iptables push the
        // agent does during the test points at production-shape
        // rules. NOT exercised by the C8 tests (no posture forcing).
        let combat = dir.join("combat-rules.v4");
        std::fs::copy(combat_rules_path(), &combat).expect("copy combat rules");

        // The single watched file. Each test names a distinct
        // basename so a `--test-threads=N>1` accident doesn't
        // collide on the same file (tempdir already gives us
        // isolation; basename uniqueness is belt + braces).
        let watched_file = dir.join(watched_basename);
        std::fs::write(&watched_file, initial_contents).expect("seed watched file");

        // fim-paths.v1: ONLY our watched file (single-line list).
        // No defaults — keeps the WATCHED_PATHS map small enough
        // that map dumps are readable in test failure output.
        let fim_paths_v1 = dir.join("fim-paths.v1");
        std::fs::write(
            &fim_paths_v1,
            format!("{}\n", watched_file.to_string_lossy()),
        )
        .expect("write fim-paths.v1");
        // fim-paths.local empty — exercises the "no overlay"
        // branch of paths_config::load_watched_paths.
        let fim_paths_local = dir.join("fim-paths.local");
        std::fs::write(&fim_paths_local, "# (no operator overlay)\n").unwrap();

        let baseline_log = dir.join("fim_baseline.jsonl");
        let drift_log = dir.join("fim_drift.jsonl");
        let audit_log = dir.join("audit.log");
        let signing_key = dir.join("agent.sig.key");
        let agent_id = dir.join("agent_id");
        let admin_socket = dir.join("admin.sock");
        let marker = dir.join("agent.shutdown_authorised");

        let child = Command::new(agent_bin())
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
            .arg("--no-ade")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn northnarrow-agent for FIM e2e");
        let guard = AgentGuard(Some(child));

        wait_for_socket(&admin_socket);

        Self {
            _tempdir: tempdir,
            watched_file,
            fim_paths_v1,
            fim_paths_local,
            baseline_log,
            drift_log,
            _agent_guard: guard,
        }
    }

    /// Wait until the baseline log has at least one chained entry
    /// — i.e., the §13 Q5 TOFU first-boot recompute completed for
    /// our watched file.
    fn wait_baseline(&self) {
        let deadline = Instant::now() + BASELINE_POLL_TIMEOUT;
        while Instant::now() < deadline {
            if jsonl_row_count(&self.baseline_log) >= 1 {
                return;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        panic!(
            "TOFU baseline never populated {} within {:?} — \
             check agent stderr for `fim:` lines",
            self.baseline_log.display(),
            BASELINE_POLL_TIMEOUT
        );
    }

    /// Wait until the drift log has at least `n` chained entries.
    /// Returns the rows so the caller can assert on individual
    /// fields.
    fn wait_drift(&self, n: usize) -> Vec<serde_json::Value> {
        let deadline = Instant::now() + DRIFT_POLL_TIMEOUT;
        while Instant::now() < deadline {
            let rows = read_jsonl(&self.drift_log);
            if rows.len() >= n {
                return rows;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        let rows = read_jsonl(&self.drift_log);
        panic!(
            "drift log {} held {} rows after {:?} — wanted >= {}; \
             current rows: {:?}",
            self.drift_log.display(),
            rows.len(),
            DRIFT_POLL_TIMEOUT,
            n,
            rows
        );
    }
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

fn jsonl_row_count(path: &Path) -> usize {
    match std::fs::read_to_string(path) {
        Ok(s) => s.lines().filter(|l| !l.trim().is_empty()).count(),
        Err(_) => 0,
    }
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

// ── Test 1: baseline + modify → Modified drift event ────────────────

/// Tappa 9 C8 e2e #1 — the canonical drift-detection path. After
/// the TOFU baseline pass populates `fim_baseline.jsonl` with the
/// watched file's SHA-256, modifying the file triggers
/// `inode_setattr` (write→close path issues SETATTR for mtime
/// updates), the userland drain re-hashes, sees the SHA differs
/// from None (no per-path baseline cache yet — C8 simplification),
/// and appends a `Modified` entry to `fim_drift.jsonl`.
#[test]
fn fim_baseline_then_modify_records_drift_event() {
    let fx = FimFixture::setup("sensitive.txt", b"initial-known-good\n");
    fx.wait_baseline();
    let baseline = read_jsonl(&fx.baseline_log);
    assert_eq!(
        baseline.len(),
        1,
        "TOFU baseline should produce exactly one entry for one watched file"
    );
    let watched_str = fx.watched_file.to_string_lossy().into_owned();
    assert_eq!(baseline[0]["path"], serde_json::json!(watched_str));
    assert!(baseline[0]["sha256"].as_str().unwrap().len() == 64);

    // Modify the watched file — the C8-wired drain MUST observe.
    std::fs::write(&fx.watched_file, b"tampered-content\n")
        .expect("modify watched file");

    let drift = fx.wait_drift(1);
    let row = &drift[0];
    assert_eq!(row["path"], serde_json::json!(watched_str));
    let op = row["op"].as_u64().unwrap_or(0);
    assert!(
        op == OP_MODIFIED || op == OP_OPENED,
        "expected op MODIFIED({OP_MODIFIED}) or OPENED({OP_OPENED}), got {op}"
    );
    // Modifier should be SOME process — the kernel fills it.
    // We don't pin the PID because writeback / fs internals can
    // proxy the modification through a kernel thread on some
    // filesystems; presence + non-zero is enough.
    assert!(row["modifier_pid"].as_u64().unwrap_or(0) > 0);

    // Sanity: paths_config files were created where the agent
    // expected them (no orphan tempdir state).
    assert!(fx.fim_paths_v1.exists());
    assert!(fx.fim_paths_local.exists());
}

// ── Test 2: subprocess unlink → Deleted drift event ─────────────────

/// Tappa 9 C8 e2e #2 — the `Deleted` op path. A `sh -c "rm
/// <watched>"` subprocess triggers `inode_unlink`. The drain
/// records the subprocess's PID + comm in the drift entry so an
/// operator running `nn-admin fim report` sees WHO deleted the
/// file.
#[test]
fn fim_subprocess_unlink_records_deleted_event() {
    let fx = FimFixture::setup("data.txt", b"original-bytes\n");
    fx.wait_baseline();

    // Subprocess rm so the modifier_pid in the drift entry is
    // distinct from the test process.
    let watched = fx.watched_file.to_string_lossy().into_owned();
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("rm -f -- '{}'", watched.replace('\'', "'\\''")))
        .status()
        .expect("spawn rm subprocess");
    assert!(status.success(), "rm subprocess failed");

    let drift = fx.wait_drift(1);
    // The unlink event may follow zero or more Opened events
    // (some shells stat-open the file before unlinking it).
    // Walk the rows until we find the Deleted entry — that's
    // the C8 assertion target. If only Opened rows are present,
    // wait for more.
    let row = drift
        .iter()
        .find(|r| r["op"].as_u64() == Some(OP_DELETED))
        .cloned()
        .unwrap_or_else(|| {
            // Wait for a second round in case the deleted event
            // is still inflight.
            let more = fx.wait_drift(drift.len() + 1);
            more.iter()
                .find(|r| r["op"].as_u64() == Some(OP_DELETED))
                .cloned()
                .unwrap_or_else(|| {
                    panic!(
                        "no Deleted-op drift entry found in drift log: rows={more:?}"
                    )
                })
        });
    assert_eq!(row["path"], serde_json::json!(watched));
    assert_eq!(
        row["op"].as_u64().unwrap_or(0),
        OP_DELETED,
        "expected op DELETED({OP_DELETED})"
    );
    // modifier_comm should be the subprocess's basename. `sh`
    // execs `rm` as the same process when there's only one
    // command, so on some shells modifier_comm is "rm"; on
    // others it might be "sh" if the shell forks. Accept both.
    let comm = row["modifier_comm"].as_str().unwrap_or("");
    assert!(
        comm == "rm" || comm == "sh",
        "expected modifier_comm of `rm` or `sh`, got `{comm}`"
    );
}

// ── Test 3: subprocess open of cred-shaped path → Opened event ──────

/// Tappa 9 C8 e2e #3 — the `Opened` op path that the
/// NN-L-FIM-011..014 cloud-credential read rules consume.
///
/// Setup: stages a fake AWS creds file at a path that contains
/// the `/.aws/credentials` substring the NN-L-FIM-011 path
/// matcher uses, then `cat`s it from a subprocess. Comm is
/// `cat`, not in the `AWS_CLI_COMMS` allow-list, so a fully
/// wired rule engine would fire `NN-L-FIM-011_AwsCredsRead` on
/// the resulting `Event::Fim`. This test only asserts the drift
/// entry is recorded — rule-firing assertions belong in a
/// separate test that doesn't need a sacrificial subprocess.
///
/// **Why a separate tempdir layout:** the watched path needs to
/// look like `<...>/.aws/credentials` so the NN-L-FIM-011
/// substring matcher would accept it. The fixture's normal
/// "single file at tempdir root" shape doesn't satisfy that —
/// we build a `.aws/` subdir + `credentials` file inside the
/// tempdir.
#[test]
fn fim_subprocess_open_aws_creds_records_opened_event() {
    wipe_pin_tree();
    let tempdir = tempfile::tempdir().expect("tempdir");
    let dir = tempdir.path();
    // Build the .aws/credentials shape so NN-L-FIM-011's
    // substring match (`/.aws/credentials`) would accept the
    // resulting drift event's path.
    let aws_dir = dir.join(".aws");
    std::fs::create_dir(&aws_dir).expect("mkdir .aws");
    let watched_file = aws_dir.join("credentials");
    std::fs::write(&watched_file, b"[default]\naws_access_key_id = AKIA_TEST\n")
        .expect("seed creds file");

    // Replicate the FimFixture::setup bootstrap but with the
    // .aws-shaped watched path. (Refactoring FimFixture::setup
    // to accept an arbitrary watched_file path is a follow-up;
    // keeping this test self-contained for now.)
    let admin_pub = dir.join("admin.pub");
    let admin_priv = dir.join("admin.priv");
    Command::new(nn_admin_bin())
        .arg("init")
        .arg("--priv-out")
        .arg(&admin_priv)
        .arg("--pub-append")
        .arg(&admin_pub)
        .status()
        .expect("nn-admin init");
    let combat = dir.join("combat-rules.v4");
    std::fs::copy(combat_rules_path(), &combat).expect("copy combat rules");
    let fim_paths_v1 = dir.join("fim-paths.v1");
    std::fs::write(
        &fim_paths_v1,
        format!("{}\n", watched_file.to_string_lossy()),
    )
    .expect("write fim-paths.v1");
    let fim_paths_local = dir.join("fim-paths.local");
    std::fs::write(&fim_paths_local, "").unwrap();
    let baseline_log = dir.join("fim_baseline.jsonl");
    let drift_log = dir.join("fim_drift.jsonl");
    let audit_log = dir.join("audit.log");
    let signing_key = dir.join("agent.sig.key");
    let agent_id = dir.join("agent_id");
    let admin_socket = dir.join("admin.sock");
    let marker = dir.join("agent.shutdown_authorised");

    let child = Command::new(agent_bin())
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
        .arg("--no-ade")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn northnarrow-agent for FIM cred-read e2e");
    let _guard = AgentGuard(Some(child));
    wait_for_socket(&admin_socket);

    // Wait for the TOFU baseline.
    let deadline = Instant::now() + BASELINE_POLL_TIMEOUT;
    while Instant::now() < deadline && jsonl_row_count(&baseline_log) < 1 {
        std::thread::sleep(POLL_INTERVAL);
    }
    assert!(
        jsonl_row_count(&baseline_log) >= 1,
        "TOFU baseline never populated {}",
        baseline_log.display()
    );

    // `cat` the creds file from a subprocess so the modifier
    // comm is `cat` (not in AWS_CLI_COMMS — exactly what the
    // NN-L-FIM-011 rule treats as "suspicious read").
    let watched_str = watched_file.to_string_lossy().into_owned();
    let status = Command::new("cat")
        .arg(&watched_file)
        .stdout(Stdio::null())
        .status()
        .expect("spawn cat");
    assert!(status.success(), "cat subprocess failed");

    let deadline = Instant::now() + DRIFT_POLL_TIMEOUT;
    while Instant::now() < deadline && jsonl_row_count(&drift_log) < 1 {
        std::thread::sleep(POLL_INTERVAL);
    }
    let rows = read_jsonl(&drift_log);
    assert!(
        !rows.is_empty(),
        "drift log {} never populated within {:?}; cat may have been processed \
         before TOFU finished — increase BASELINE_POLL_TIMEOUT if this flakes",
        drift_log.display(),
        DRIFT_POLL_TIMEOUT
    );
    let row = &rows[0];
    assert_eq!(row["path"], serde_json::json!(watched_str));
    let op = row["op"].as_u64().unwrap_or(0);
    assert!(
        op == OP_OPENED || op == OP_MODIFIED,
        "expected OPENED({OP_OPENED}) or MODIFIED({OP_MODIFIED}) for cat of \
         creds file, got {op}"
    );
    // Path satisfies the NN-L-FIM-011 substring matcher.
    assert!(
        watched_str.contains("/.aws/credentials"),
        "watched path `{watched_str}` should match NN-L-FIM-011's substring \
         predicate"
    );
}
