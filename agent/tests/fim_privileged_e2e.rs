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

mod common;
use common::{install_to_priv_bin, InstalledBin};

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
const OP_CREATED: u64 = 2;
const OP_DELETED: u64 = 3;
#[allow(dead_code)]
const OP_RENAMED: u64 = 4;
#[allow(dead_code)]
const OP_LINKED: u64 = 5;
const OP_OPENED: u64 = 6;
const OP_ATTR_CHANGED: u64 = 8;

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

/// Tempdir layout the FIM privileged tests share. Holding every
/// per-test file path in one struct keeps the spawn + assertion
/// helpers readable.
struct FimFixture {
    _tempdir: tempfile::TempDir,
    /// Path the test watches (single-file watched set — keeps
    /// the e2e blast radius small).
    watched_file: PathBuf,
    /// A watched directory next to it, when the test asked for one
    /// ([`FimFixture::setup_watching_dir`]).
    watched_dir: Option<PathBuf>,
    fim_paths_v1: PathBuf,
    fim_paths_local: PathBuf,
    baseline_log: PathBuf,
    drift_log: PathBuf,
    /// Returned so the test can SIGQUIT the agent at end-of-test.
    /// `Option` so `Drop` can take ownership.
    _agent_guard: AgentGuard,
    /// External audit NN-AUD-423 (TST-017): the agent runs from a
    /// root-owned copy (`common::install_to_priv_bin`), not from
    /// `target/` under the user's home. Dropped after the agent stops.
    _installed_agent: InstalledBin,
}

/// Lab PR 163's lesson, here too: the agent stops before the fields drop.
/// Fields drop in declaration order, so `_tempdir` went first with the
/// agent still running on the chains, keys and socket it holds there.
impl Drop for FimFixture {
    fn drop(&mut self) {
        if let Some(mut c) = self._agent_guard.0.take() {
            common::quit_agent(&mut c);
        }
    }
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
        Self::setup_watching_dir(watched_basename, initial_contents, None)
    }

    /// [`Self::setup`], plus the directory `dir_name` (created empty in the
    /// tempdir) on the watch list: files dropped into it are its runtime
    /// children.
    fn setup_watching_dir(
        watched_basename: &str,
        initial_contents: &[u8],
        dir_name: Option<&str>,
    ) -> Self {
        wipe_pin_tree();
        let installed_agent = install_to_priv_bin(Path::new(agent_bin()));
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
        let watched_dir = dir_name.map(|name| {
            let d = dir.join(name);
            std::fs::create_dir(&d).expect("create watched dir");
            d
        });

        // fim-paths.v1: ONLY our watched file (single-line list), and the
        // directory when asked for. No defaults — keeps the WATCHED_PATHS
        // map small enough that map dumps are readable in test failure
        // output.
        let fim_paths_v1 = dir.join("fim-paths.v1");
        let mut list = format!("{}\n", watched_file.to_string_lossy());
        if let Some(d) = &watched_dir {
            list.push_str(&format!("{}\n", d.to_string_lossy()));
        }
        std::fs::write(&fim_paths_v1, list).expect("write fim-paths.v1");
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

        common::require_bpftool();
        let child = Command::new(&installed_agent.path)
            .env(
                common::OWN_DEFAULT_LISTS_ENV.0,
                common::OWN_DEFAULT_LISTS_ENV.1,
            )
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
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn northnarrow-agent for FIM e2e");
        let guard = AgentGuard(Some(child));

        wait_for_socket(&admin_socket);

        Self {
            _tempdir: tempdir,
            watched_file,
            watched_dir,
            fim_paths_v1,
            fim_paths_local,
            baseline_log,
            drift_log,
            _agent_guard: guard,
            _installed_agent: installed_agent,
        }
    }

    /// Wait until the baseline log has at least one chained entry
    /// — i.e., the §13 Q5 TOFU first-boot recompute completed for
    /// our watched file.
    fn wait_baseline(&self) {
        let deadline = Instant::now() + BASELINE_POLL_TIMEOUT;
        while Instant::now() < deadline {
            if !common::read_jsonl_strict(&self.baseline_log).is_empty() {
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
    /// Wait for a drift row on `path` with op `op` (others may come
    /// first: a write is a setattr as well as a change of content).
    fn wait_drift_op(&self, path: &str, op: u64) -> serde_json::Value {
        let deadline = Instant::now() + DRIFT_POLL_TIMEOUT;
        loop {
            let rows = common::read_jsonl_strict(&self.drift_log);
            if let Some(row) = rows
                .iter()
                .find(|r| r["path"] == serde_json::json!(path) && r["op"].as_u64() == Some(op))
            {
                return row.clone();
            }
            assert!(
                Instant::now() < deadline,
                "no drift row with op {op} on {path} within {DRIFT_POLL_TIMEOUT:?}; rows: {rows:?}"
            );
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    fn wait_drift(&self, n: usize) -> Vec<serde_json::Value> {
        let deadline = Instant::now() + DRIFT_POLL_TIMEOUT;
        while Instant::now() < deadline {
            let rows = common::read_jsonl_strict(&self.drift_log);
            if rows.len() >= n {
                return rows;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        let rows = common::read_jsonl_strict(&self.drift_log);
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
    let baseline = common::read_jsonl_strict(&fx.baseline_log);
    assert_eq!(
        baseline.len(),
        1,
        "TOFU baseline should produce exactly one entry for one watched file"
    );
    let watched_str = fx.watched_file.to_string_lossy().into_owned();
    assert_eq!(baseline[0]["path"], serde_json::json!(watched_str));
    assert!(baseline[0]["sha256"].as_str().unwrap().len() == 64);

    // Modify the watched file — the C8-wired drain MUST observe.
    std::fs::write(&fx.watched_file, b"tampered-content\n").expect("modify watched file");

    // External audit TST-004: the row asserted is the Modified one on the
    // watched path (accepting an Opened row hid a real gap), and a read is
    // never recorded as drift (BUG-012 v2).
    let row = fx.wait_drift_op(&watched_str, OP_MODIFIED);
    assert!(
        common::read_jsonl_strict(&fx.drift_log)
            .iter()
            .all(|r| r["op"].as_u64() != Some(OP_OPENED)),
        "a read is not drift"
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

// ── Test 1b: chmod u+s, content unchanged → attribute drift ──────────

/// External audit TST-004 (Wave 2): `chmod u+s` changes no byte of the
/// file, and the drain dropped it as a no-op touch — a set-uid bit on a
/// watched binary left no trace. It is recorded as `AttrChanged` with the
/// mode before and after.
#[test]
fn fim_chmod_setuid_records_attribute_drift() {
    use std::os::unix::fs::PermissionsExt;
    let fx = FimFixture::setup("tool.bin", b"#!/bin/true\n");
    fx.wait_baseline();
    let watched_str = fx.watched_file.to_string_lossy().into_owned();
    let before = std::fs::metadata(&fx.watched_file)
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    std::fs::set_permissions(
        &fx.watched_file,
        std::fs::Permissions::from_mode(before | 0o4000),
    )
    .expect("chmod u+s");

    let row = fx.wait_drift_op(&watched_str, OP_ATTR_CHANGED);
    assert_eq!(row["attrs"]["mode_before"].as_u64(), Some(before as u64));
    assert_eq!(
        row["attrs"]["mode_after"].as_u64(),
        Some((before | 0o4000) as u64)
    );
    assert_eq!(
        row["baseline_sha256"], row["new_sha256"],
        "the content did not change"
    );
}

// ── Test 1c: a child whose name is not UTF-8 ────────────────────────

/// External audit NN-AUD-291 (FIMP-012): a file dropped into a watched
/// directory under a name that is not UTF-8 (`ev\xffil`) is named with a
/// `\xNN` escape, enrolled by its own bytes, and its later append is a
/// `Modified` row. Before, the leaf was decoded lossily (U+FFFD): the
/// `Created` row named a file that does not exist, the file was never
/// watched, and the append left no row.
#[test]
fn fim_child_with_a_non_utf8_name_is_watched_and_its_append_recorded() {
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    let fx = FimFixture::setup_watching_dir("anchor.txt", b"anchor\n", Some("drop.d"));
    fx.wait_baseline();
    let dir = fx.watched_dir.clone().expect("watched dir");
    let file = dir.join(std::ffi::OsStr::from_bytes(b"ev\xffil"));
    let shown = format!("{}/ev\\xffil", dir.to_string_lossy());
    std::fs::write(&file, b"first line\n").expect("drop the child");
    // The hook fires before the create: the row's hash may be of no file
    // yet. Its name is the escaped one.
    let created = fx.wait_drift_op(&shown, OP_CREATED);
    // Let the enrollment land before the in-place edit.
    std::thread::sleep(Duration::from_millis(500));
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&file)
        .expect("open the child");
    f.write_all(b"appended\n").expect("append");
    drop(f);
    // The child is watched: an edit in place is a Modified row (the first
    // write's close may already give one; on the code before, none came).
    let modified = fx.wait_drift_op(&shown, OP_MODIFIED);
    assert!(modified["new_sha256"].is_string(), "{modified}");
    assert_eq!(created["path"], modified["path"]);
    std::fs::remove_file(&file).expect("clean up the child");
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
                    panic!("no Deleted-op drift entry found in drift log: rows={more:?}")
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
/// wired rule engine fires `NN-L-FIM-011_AwsCredsRead` on the
/// resulting `Event::Fim`. Since BUG-012 v2 a read is NEVER an
/// integrity drift: the drain forwards the credential-path `Opened`
/// to the rule engine silently and writes no `fim_drift.jsonl`
/// row, so this test asserts the two observable halves of that
/// contract — the detection record lands in `--detections-file`
/// and the drift log stays empty. (Before 2026-10-10 it waited for
/// a drift row and failed on every kernel; the lab never ran it.)
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
    // Declared before the agent's guard: dropped after the agent stops.
    let installed_agent = install_to_priv_bin(Path::new(agent_bin()));
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
    let init = Command::new(nn_admin_bin())
        .arg("init")
        .arg("--priv-out")
        .arg(&admin_priv)
        .arg("--pub-append")
        .arg(&admin_pub)
        .status()
        .expect("nn-admin init");
    assert!(init.success(), "nn-admin init failed");
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
    // Per-test detection store: the credential-read verdict is the
    // artefact this test waits for, and the default path is the
    // production chain under /var/lib/northnarrow.
    let detections_log = dir.join("detections.jsonl");
    let status_events_log = dir.join("status_events.jsonl");

    common::require_bpftool();
    let child = Command::new(&installed_agent.path)
        .env(
            common::OWN_DEFAULT_LISTS_ENV.0,
            common::OWN_DEFAULT_LISTS_ENV.1,
        )
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
        .arg("--detections-file")
        .arg(&detections_log)
        .arg("--status-events-file")
        .arg(&status_events_log)
        .arg("--fim-paths-v1")
        .arg(&fim_paths_v1)
        .arg("--fim-paths-local")
        .arg(&fim_paths_local)
        .arg("--fim-baseline-file")
        .arg(&baseline_log)
        .arg("--fim-drift-file")
        .arg(&drift_log)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn northnarrow-agent for FIM cred-read e2e");
    let _guard = AgentGuard(Some(child));
    wait_for_socket(&admin_socket);

    // Wait for the TOFU baseline.
    let deadline = Instant::now() + BASELINE_POLL_TIMEOUT;
    while Instant::now() < deadline && common::read_jsonl_strict(&baseline_log).is_empty() {
        std::thread::sleep(POLL_INTERVAL);
    }
    assert!(
        !common::read_jsonl_strict(&baseline_log).is_empty(),
        "TOFU baseline never populated {}",
        baseline_log.display()
    );

    // `cat` the creds file from a subprocess so the modifier
    // comm is `cat` (not in AWS_CLI_COMMS — exactly what the
    // NN-L-FIM-011 rule treats as "suspicious read").
    let watched_str = watched_file.to_string_lossy().into_owned();
    assert!(
        watched_str.contains("/.aws/credentials"),
        "watched path `{watched_str}` should match NN-L-FIM-011's substring \
         predicate"
    );
    // The verdict is KillProcess on `cat`; it has normally exited by
    // the time the event is drained, so its exit status is not
    // asserted — only that it ran.
    let _ = Command::new("cat")
        .arg(&watched_file)
        .stdout(Stdio::null())
        .status()
        .expect("spawn cat");
    let deadline = Instant::now() + DRIFT_POLL_TIMEOUT;
    let mut hit: Option<serde_json::Value> = None;
    while Instant::now() < deadline && hit.is_none() {
        hit = common::read_jsonl_strict(&detections_log)
            .into_iter()
            .find(|r| r["rule_id"] == serde_json::json!("NN-L-FIM-011_AwsCredsRead"));
        if hit.is_none() {
            std::thread::sleep(POLL_INTERVAL);
        }
    }
    let hit = hit.unwrap_or_else(|| {
        panic!(
            "no NN-L-FIM-011_AwsCredsRead record in {} within {:?}; records seen: {:?}",
            detections_log.display(),
            DRIFT_POLL_TIMEOUT,
            common::read_jsonl_strict(&detections_log)
                .iter()
                .map(|r| r["rule_id"].clone())
                .collect::<Vec<_>>()
        )
    });
    assert_eq!(hit["severity"], serde_json::json!("High"), "record: {hit}");
    // BUG-012 v2: a read is not integrity drift — the drift log must
    // still be empty after the detection was recorded.
    assert_eq!(
        common::read_jsonl_strict(&drift_log).len(),
        0,
        "a credential read must not produce a drift row (BUG-012 v2): {:?}",
        common::read_jsonl_strict(&drift_log)
    );
}

// ── Polish #2: BaselineCache no-op-touch suppression ────────────────

/// Tappa 9 polish #2 e2e — cache suppression for `Modified`
/// op when content didn't change. `touch -t` on a watched file
/// fires BOTH `inode_setattr` (mtime update → Modified) and
/// `file_open` (touch opens the file → Opened). The cache
/// suppresses the Modified row when content_sha matches; the
/// Opened row always emits per `process_drift`'s policy
/// (Opened doesn't get content-equality suppression because
/// the NN-L-FIM-011..014 cred-read rules care WHO opens
/// regardless of content).
///
/// Asserts ZERO `op=Modified` rows after a sequence of touch -t
/// calls. Opened rows are unavoidable and not the test target.
#[test]
fn fim_baseline_cache_suppresses_noop_modified() {
    let fx = FimFixture::setup("steady.txt", b"unchanged-content\n");
    fx.wait_baseline();

    // Sanity: drift log is empty after the TOFU baseline pass —
    // the cache was populated from the chain post-recompute, so
    // no drift entries yet.
    let pre = common::read_jsonl_strict(&fx.drift_log);
    assert!(
        pre.is_empty(),
        "drift log should be empty post-baseline before any touch: {pre:?}"
    );

    // Touch the watched file 5 times with different mtimes —
    // mtime changes but content stays "unchanged-content\n".
    // Without the cache, each `inode_setattr` event would land
    // a Modified row. With the cache, content-equality check
    // skips the Modified emit; only Opened rows from touch's
    // file_open syscall remain.
    let watched = fx.watched_file.to_string_lossy().into_owned();
    for stamp in &[
        "202301010000.00",
        "202302010000.00",
        "202303010000.00",
        "202304010000.00",
        "202305010000.00",
    ] {
        let status = std::process::Command::new("touch")
            .arg("-t")
            .arg(stamp)
            .arg(&watched)
            .status()
            .expect("spawn touch");
        assert!(status.success(), "touch failed for stamp {stamp}");
    }

    // External audit NN-AUD-228: not a fixed sleep (a drain slower than
    // it passed vacuously) but a barrier: a real content change after the
    // touches, its Modified row waited for. The drain reads its ring in
    // order, so by then every touch has been judged. Since BUG-012 v2 the
    // touches' opens leave no row to count, hence a write.
    std::fs::write(&fx.watched_file, b"barrier-content\n").expect("barrier write");
    common::wait_jsonl_row(
        &fx.drift_log,
        DRIFT_POLL_TIMEOUT,
        "Modified row of the barrier write",
        |r| {
            r["path"].as_str() == Some(watched.as_str())
                && r["op"].as_u64() == Some(OP_MODIFIED)
                && r["new_sha256"] != r["baseline_sha256"]
        },
    );

    // A no-op touch recorded as Modified would carry an unchanged hash.
    let rows = common::read_jsonl_strict(&fx.drift_log);
    let noop_rows: Vec<_> = rows
        .iter()
        .filter(|r| {
            r["op"].as_u64() == Some(OP_MODIFIED) && r["new_sha256"] == r["baseline_sha256"]
        })
        .collect();
    assert!(
        noop_rows.is_empty(),
        "expected ZERO Modified drift rows for the no-op touches \
         (cache suppression should fire); got {} rows: {noop_rows:?}",
        noop_rows.len()
    );
}
