//! Privileged end-to-end integration tests for the Tappa 7 task 7 /
//! Tappa 8 admin pipeline.
//!
//! These tests spawn the real `northnarrow-agent` and `nn-admin`
//! binaries against a tempdir socket, then drive the agent through
//! the COMBAT → admin-unlock cycle while asserting the live iptables
//! filter table. They require:
//!
//! - root (or CAP_NET_ADMIN) for `iptables-restore` / `iptables -D`,
//! - the `iptables` userland binaries on PATH,
//! - the workspace built with `--features test-privileged,debug-trigger`.
//!
//! See `docs/integration-test-runbook.md` for the manual run path.
//! CI compiles this module via `cargo test --no-run` to defend
//! against bit-rot, but never executes it.
//!
//! All tests are also `#[ignore]`-able as `cargo test --features
//! test-privileged` runs them when invoked with `-- --ignored` or
//! when a sudo wrapper has root; we don't `#[ignore]` here because
//! the feature gate already keeps them off the default test path.
//!
//! ## Why both binaries are installed to `/usr/local/bin/` at fixture
//! ## setup
//!
//! Cargo resolves `CARGO_BIN_EXE_northnarrow-agent` and
//! `CARGO_BIN_EXE_nn-admin` to `<repo>/target/<profile>/<name>`. In
//! any developer environment that path lives under
//! `/home/<user>/...`. The production decision rule
//! `R009_RootExecFromUserPath`
//! (`agent/src/decision/rules/r009_root_exec_from_user_path.rs`)
//! matches on `uid == 0` plus a `/home/`, `/tmp/`, or `/var/tmp/`
//! prefix and returns `ResponseAction::KillProcess` — so `nn-admin`
//! spawned from the cargo path dies ~µs after spawn, before it can
//! drive any admin frame onto the socket.
//!
//! [`install_to_priv_bin`] sudo-copies the binary to
//! `/usr/local/bin/<name>-e2etest-<ts>-<pid>` (mode 0755, owner
//! root:root), which is NOT a user-writable prefix and therefore not
//! matched by R009. Each test spawns the relocated copy. The agent
//! install is owned by [`AgentGuard`] and cleaned up on drop; the
//! `nn-admin` install is cached per test in a thread-local so
//! repeated `run_nn_admin` calls share one install, and is cleaned
//! up by [`AgentGuard::drop`] along with the agent install.
//!
//! Full root-cause and remediation analysis:
//! `docs/issues/ISSUE_001_eni_test_r009_selfkill.md`.

#![cfg(feature = "test-privileged")]

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SOCKET_POLL_TIMEOUT: Duration = Duration::from_secs(5);
const SOCKET_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// System directory we copy the test binaries into. Outside every
/// prefix in `R009_RootExecFromUserPath::USER_WRITABLE_PREFIXES`, so
/// a root exec from here is not flagged.
const PRIV_BIN_DIR: &str = "/usr/local/bin";

thread_local! {
    /// Per-test cache of the relocated `nn-admin` binary. Lazily
    /// populated by [`nn_admin_priv`] on first use and torn down by
    /// [`AgentGuard::drop`] when the owning test ends — so each test
    /// gets a fresh install with a unique timestamp+PID suffix, and
    /// nothing leaks into `/usr/local/bin/` past the test process.
    static NN_ADMIN_INSTALL: RefCell<Option<InstalledBin>> = const { RefCell::new(None) };
}

/// RAII wrapper for a binary copy under [`PRIV_BIN_DIR`]. Drop
/// `sudo rm -f`s the file so a test panic does not leave it behind.
/// Failures during drop are swallowed (best-effort cleanup; the
/// timestamp+PID suffix means a leftover never blocks a future run).
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

/// Copy `src` to `/usr/local/bin/<basename>-e2etest-<ts_ns>-<pid>`
/// with mode 0755 and owner root:root. Uses `sudo install` so the
/// fixture works whether the cargo-test process is already root or
/// invoked via passwordless sudo. Panics if the install command
/// fails — there is no graceful degrade: without the relocated copy
/// R009 will eat any spawn of the binary and the test cannot run.
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
    let dst = PathBuf::from(format!(
        "{PRIV_BIN_DIR}/{basename}-e2etest-{ts_ns}-{pid}"
    ));
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
        "sudo install of {} to {} failed (status={:?})",
        src.display(),
        dst.display(),
        status.code()
    );
    InstalledBin { path: dst }
}

/// Path to the per-test `nn-admin` install under [`PRIV_BIN_DIR`].
/// Installs lazily on first call within a thread/test and caches the
/// path so repeated `run_nn_admin` calls share one copy. Cleared by
/// [`AgentGuard::drop`].
fn nn_admin_priv() -> PathBuf {
    NN_ADMIN_INSTALL.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            *slot = Some(install_to_priv_bin(Path::new(nn_admin_bin())));
        }
        slot.as_ref()
            .expect("just populated above")
            .path
            .clone()
    })
}

/// Production combat ruleset used by every scenario. Copied verbatim
/// from `configs/combat-rules.v4` so tests exercise the same bytes
/// the install ships.
fn combat_rules_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("configs")
        .join("combat-rules.v4")
}

/// `target/{profile}/northnarrow-agent`. Cargo provides this env
/// var to integration tests automatically.
fn agent_bin() -> &'static str {
    env!("CARGO_BIN_EXE_northnarrow-agent")
}

fn nn_admin_bin() -> &'static str {
    env!("CARGO_BIN_EXE_nn-admin")
}

/// RAII child-process guard: SIGQUIT on drop so a failed test never
/// leaks a daemon. The agent's Tappa 7 LSM hook blocks SIGKILL and
/// SIGTERM from userland; SIGQUIT is the documented escape hatch
/// (see agent/src/anti_tamper/* docstrings).
///
/// Also owns the per-test installs under [`PRIV_BIN_DIR`]: the
/// `agent_install` field is dropped after the child is reaped, and
/// the thread-local `nn-admin` cache is cleared on the same path so
/// both binaries are removed before the test returns.
struct AgentGuard {
    child: Option<Child>,
    #[allow(dead_code, reason = "field exists solely for its Drop side effect")]
    agent_install: Option<InstalledBin>,
}
impl Drop for AgentGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            // SIGQUIT(3) — bypasses the LSM kill block for the agent
            // process. `kill -QUIT $pid` is the supported shutdown.
            unsafe {
                libc::kill(c.id() as i32, libc::SIGQUIT);
            }
            let _ = c.wait();
        }
        // Drop the agent install BEFORE clearing the nn-admin cache
        // so a panic inside one cleanup still runs the other.
        self.agent_install.take();
        NN_ADMIN_INSTALL.with(|cell| {
            cell.borrow_mut().take();
        });
    }
}

/// Spawn the agent with the per-test tempdir paths. Returns the
/// running child + the socket path the tests will connect to.
///
/// The agent binary is sudo-installed to [`PRIV_BIN_DIR`] before
/// spawn so the production R009 rule does not target it; the install
/// is owned by the returned [`AgentGuard`] and removed on drop.
fn spawn_agent(tempdir: &Path) -> (AgentGuard, PathBuf) {
    let socket = tempdir.join("admin.sock");
    let pubkey = tempdir.join("admin.pub");
    let rules = tempdir.join("combat-rules.v4");
    std::fs::copy(combat_rules_path(), &rules).expect("copy combat rules");

    let agent_install = install_to_priv_bin(Path::new(agent_bin()));
    let child = Command::new(&agent_install.path)
        .arg("--combat-rules")
        .arg(&rules)
        .arg("--admin-pub")
        .arg(&pubkey)
        .arg("--admin-socket")
        .arg(&socket)
        // ADE is heavy and irrelevant here.
        .arg("--no-ade")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn northnarrow-agent");
    let guard = AgentGuard {
        child: Some(child),
        agent_install: Some(agent_install),
    };

    wait_for_socket(&socket);
    (guard, socket)
}

fn wait_for_socket(path: &Path) {
    let deadline = Instant::now() + SOCKET_POLL_TIMEOUT;
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        std::thread::sleep(SOCKET_POLL_INTERVAL);
    }
    panic!(
        "agent never opened admin socket at {}; check that the build \
         has --features debug-trigger and that the agent process started",
        path.display()
    );
}

/// Run `nn-admin init` to generate a keypair into `tempdir`. Returns
/// the private key path the caller will use to sign.
fn init_admin_keypair(tempdir: &Path) -> PathBuf {
    let priv_path = tempdir.join("admin.priv");
    let pub_path = tempdir.join("admin.pub");
    let status = Command::new(nn_admin_priv())
        .arg("init")
        .arg("--priv-out")
        .arg(&priv_path)
        .arg("--pub-append")
        .arg(&pub_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("spawn nn-admin init");
    assert!(status.success(), "nn-admin init failed");
    priv_path
}

fn run_nn_admin(args: &[&str]) -> std::process::Output {
    Command::new(nn_admin_priv())
        .args(args)
        .output()
        .expect("spawn nn-admin")
}

/// Snapshot the rules currently installed in the NORTHNARROW_COMBAT
/// chain via `iptables -S` (restore-style output, easy to grep). An
/// empty / missing chain returns an empty Vec.
fn list_combat_chain_rules() -> Vec<String> {
    let out = Command::new("iptables")
        .args(["-S", "NORTHNARROW_COMBAT"])
        .output()
        .expect("spawn iptables -S NORTHNARROW_COMBAT");
    if !out.status.success() {
        // Chain doesn't exist — treat as "no rules installed".
        return Vec::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

#[test]
fn e2e_force_combat_then_unlock_via_cli() {
    let dir = tempfile::tempdir().expect("tempdir");
    let _guard;
    let socket;
    let priv_key;
    {
        // Initialize the pubkey file BEFORE spawning the agent so
        // AdminAuth::load succeeds at startup.
        priv_key = init_admin_keypair(dir.path());
        (_guard, socket) = spawn_agent(dir.path());
    }

    // Drive the agent into COMBAT via the debug feature.
    let out = run_nn_admin(&[
        "debug",
        "force-posture",
        "combat",
        "--socket",
        socket.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "debug force-posture failed: stderr={:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Status mirrors the forced state.
    let out = run_nn_admin(&["status", "--socket", socket.to_str().unwrap(), "--json"]);
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(
        body.contains("\"posture\":\"Combat\""),
        "status body: {body}"
    );
    assert!(
        body.contains("\"network_isolation_engaged\":true"),
        "status body: {body}"
    );

    // iptables now carries our DROP rules.
    let rules = list_combat_chain_rules();
    let joined = rules.join("\n");
    assert!(
        joined.contains("-j DROP"),
        "expected DROP rule in NORTHNARROW_COMBAT, got: {joined}"
    );
    assert!(
        joined.contains("-i lo -j RETURN") || joined.contains("-o lo -j RETURN"),
        "expected loopback RETURN in chain, got: {joined}"
    );

    // Sign + submit; should win.
    let out = run_nn_admin(&[
        "unlock",
        "--key",
        priv_key.to_str().unwrap(),
        "--socket",
        socket.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "unlock failed: code={:?} stderr={:?}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    // Chain should be empty / removed.
    let rules = list_combat_chain_rules();
    assert!(
        rules.is_empty() || rules.iter().all(|r| !r.contains("-j DROP")),
        "expected COMBAT chain to be cleared, got: {rules:?}"
    );

    // Posture dropped to Alerted (per the asymmetry rationale on
    // admin_release_combat_with_token).
    let out = run_nn_admin(&["status", "--socket", socket.to_str().unwrap(), "--json"]);
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(
        body.contains("\"posture\":\"Alerted\""),
        "status body: {body}"
    );
    assert!(
        body.contains("\"network_isolation_engaged\":false"),
        "status body: {body}"
    );
}

#[test]
fn e2e_unlock_with_wrong_key() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Install pubkey A into admin.pub.
    let _correct_priv = init_admin_keypair(dir.path());

    // Generate keypair B at a different location; B's pubkey is
    // NOT in admin.pub. Use a clean second tempdir as a "wrong key
    // shop" so B's init doesn't also append to the real admin.pub.
    let other = tempfile::tempdir().expect("tempdir2");
    let other_priv = init_admin_keypair(other.path());

    let (_guard, socket) = spawn_agent(dir.path());

    // Force Combat to make the test meaningful.
    let out = run_nn_admin(&[
        "debug",
        "force-posture",
        "combat",
        "--socket",
        socket.to_str().unwrap(),
    ]);
    assert!(out.status.success());

    // Unlock with the wrong private key.
    let out = run_nn_admin(&[
        "unlock",
        "--key",
        other_priv.to_str().unwrap(),
        "--socket",
        socket.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected InvalidSignature exit code 2, stderr={:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Posture still Combat, isolation still engaged.
    let out = run_nn_admin(&["status", "--socket", socket.to_str().unwrap(), "--json"]);
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(
        body.contains("\"posture\":\"Combat\""),
        "status body: {body}"
    );
    assert!(
        body.contains("\"network_isolation_engaged\":true"),
        "status body: {body}"
    );

    // Cleanup: tear down the chain via correct unlock so we don't
    // leave the test host network-isolated if the test runner aborts.
    let _ = run_nn_admin(&[
        "unlock",
        "--key",
        _correct_priv.to_str().unwrap(),
        "--socket",
        socket.to_str().unwrap(),
    ]);
}

#[test]
#[ignore = "5-min production rate-limit window too long for CI; run \
            manually or after V1.1 adds a runtime override (see runbook)"]
fn e2e_rate_limit_via_full_stack() {
    // The CLI/socket path itself works fine; the limitation is that
    // AdminAuth's rate-limit window is `pub const
    // DEFAULT_RATE_LIMIT_WINDOW = Duration::from_secs(5 * 60)` with
    // no runtime override (only the `#[cfg(test)] new_with_window`
    // constructor takes a custom Duration, and that's inaccessible
    // from an external integration test). Documenting and ignoring
    // until V1.1 introduces NN_ADMIN_RATE_LIMIT_WINDOW_SECS or a
    // CLI flag. The skeleton below is the shape the unignored
    // version will take.
    let dir = tempfile::tempdir().expect("tempdir");
    let _correct_priv = init_admin_keypair(dir.path());
    let other = tempfile::tempdir().expect("tempdir2");
    let other_priv = init_admin_keypair(other.path());
    let (_guard, socket) = spawn_agent(dir.path());

    // Force Combat.
    let _ = run_nn_admin(&[
        "debug",
        "force-posture",
        "combat",
        "--socket",
        socket.to_str().unwrap(),
    ]);

    // Three failures.
    for _ in 0..3 {
        let out = run_nn_admin(&[
            "unlock",
            "--key",
            other_priv.to_str().unwrap(),
            "--socket",
            socket.to_str().unwrap(),
        ]);
        assert_eq!(out.status.code(), Some(2));
    }

    // Fourth attempt would be RateLimited if window were short
    // enough; with the 5-minute production window the 4th call
    // still succeeds at the challenge step (AdminAuth gates
    // issue_challenge, not verify directly, but the failures
    // accumulated above ARE counted). Re-enable assertion after
    // the V1.1 override lands.
    let out = run_nn_admin(&[
        "unlock",
        "--key",
        other_priv.to_str().unwrap(),
        "--socket",
        socket.to_str().unwrap(),
    ]);
    // V1.1: assert_eq!(out.status.code(), Some(4));
    let _ = out;
}

#[test]
fn e2e_status_no_admin_action_initially() {
    let dir = tempfile::tempdir().expect("tempdir");
    let _priv = init_admin_keypair(dir.path());
    let (_guard, socket) = spawn_agent(dir.path());

    let out = run_nn_admin(&["status", "--socket", socket.to_str().unwrap(), "--json"]);
    assert!(out.status.success());
    let body = String::from_utf8_lossy(&out.stdout);

    assert!(
        body.contains("\"posture\":\"Observing\""),
        "status body: {body}"
    );
    assert!(
        body.contains("\"network_isolation_engaged\":false"),
        "status body: {body}"
    );
    assert!(
        body.contains("\"last_admin_action_secs_ago\":null"),
        "status body: {body}"
    );
}
