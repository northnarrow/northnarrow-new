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

#![cfg(feature = "test-privileged")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod common;
use common::EniIptablesGuard;

// The agent's start (BTF, the eBPF object, the rules) took ~5 s on a lab
// host running two other guests: the 5-s wait failed a gate run with the
// socket about to open.
const SOCKET_POLL_TIMEOUT: Duration = Duration::from_secs(20);
const SOCKET_POLL_INTERVAL: Duration = Duration::from_millis(50);

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

/// RAII child-process guard: stops the agent on drop so a failed test
/// never leaks a daemon. The task_kill hook refuses every signal from the
/// (unprotected) test runner while the agent is in PROTECTED_PIDS, so
/// `common::quit_agent` evicts the sudo subtree first, then SIGQUITs it —
/// possible only while the BPF guard observes (`debug-trigger` builds),
/// and a failure fails the test (external audit TST-010).
struct AgentGuard(Option<Child>);
impl Drop for AgentGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            common::quit_agent(&mut c);
        }
    }
}

/// Per-test handles carried by [`spawn_agent`]: the installed
/// agent + nn-admin RAII guards (Drop sudo-removes the
/// /usr/local/bin/ copies) plus the socket + the nn-admin path
/// the tests invoke as their CLI binary. R009-safe via the
/// PHASE_D_003 `install_to_priv_bin` pattern — agent + nn-admin
/// both run from /usr/local/bin/ (NOT user-writable) so the
/// `R009_RootExecFromUserPath` rule never matches.
struct AgentHandles {
    socket: PathBuf,
    /// Path the tests pass to `run_nn_admin` — the installed
    /// nn-admin under /usr/local/bin/. Holding the corresponding
    /// `InstalledBin` in `_installed_admin` keeps it alive.
    nn_admin_path: PathBuf,
    _installed_agent: InstalledBin,
    _installed_admin: InstalledBin,
}

/// Spawn the agent from a sudo-installed copy under
/// /usr/local/bin/ so the per-spawn nn-admin invocations don't
/// trip the agent's `R009_RootExecFromUserPath` rule (which
/// kills any root spawn originating from /home/, /tmp/, etc.).
///
/// Mirrors `spawn_agent_b5_with_installs` for the simpler
/// legacy callers that don't need the B5-era signing-key /
/// audit-log / shutdown-marker per-test overrides.
fn spawn_agent(tempdir: &Path) -> (AgentGuard, AgentHandles) {
    let (installed_agent, installed_admin) = install_priv_bins();
    let socket = tempdir.join("admin.sock");
    let pubkey = tempdir.join("admin.pub");
    let rules = tempdir.join("combat-rules.v4");
    std::fs::copy(combat_rules_path(), &rules).expect("copy combat rules");

    // Spawn the installed (root-owned, /usr/local/bin/) agent
    // under sudo so it inherits root privileges + bypasses
    // R009. AgentGuard's SIGQUIT-on-drop still works against
    // the root subprocess because the kill comes from the test
    // process (also root via the outer `sudo cargo test`).
    common::require_bpftool();
    let child = Command::new("sudo")
        .arg(&installed_agent.path)
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
        .expect("spawn northnarrow-agent (installed copy)");
    let guard = AgentGuard(Some(child));

    wait_for_socket(&socket);
    let handles = AgentHandles {
        socket,
        nn_admin_path: installed_admin.path.clone(),
        _installed_agent: installed_agent,
        _installed_admin: installed_admin,
    };
    (guard, handles)
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

/// Run `nn-admin init` to generate a keypair into `tempdir`.
/// The `nn_admin_path` is the binary to invoke — either the
/// cargo target path (pre-install, when no agent is running so
/// R009 is harmless) or the /usr/local/bin/ install. Returns
/// the private key path the caller will use to sign.
fn init_admin_keypair_at(nn_admin_path: &Path, tempdir: &Path) -> PathBuf {
    let priv_path = tempdir.join("admin.priv");
    let pub_path = tempdir.join("admin.pub");
    let status = Command::new(nn_admin_path)
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

/// Pre-install convenience: init keypair using the cargo target
/// path BEFORE the agent boots (R009 only fires on a running
/// agent, so target/release/nn-admin is safe here).
fn init_admin_keypair(tempdir: &Path) -> PathBuf {
    init_admin_keypair_at(Path::new(nn_admin_bin()), tempdir)
}

/// Run nn-admin via the supplied (installed) path. Tests spawned
/// via [`spawn_agent`] pass `handles.nn_admin_path` here so the
/// subprocess runs from /usr/local/bin/ and the agent's R009
/// rule doesn't kill it mid-op.
fn run_nn_admin_at(nn_admin_path: &Path, args: &[&str]) -> std::process::Output {
    Command::new(nn_admin_path)
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

/// Poll `nn-admin status --json` until the COMBAT ladder has engaged
/// network isolation (ISOLATE stage), or panic after the deadline. The
/// ladder's investigate window is 30 s by default; 75 s leaves room for
/// the tick cadence on a slow guest.
fn wait_for_isolation(nn: &std::path::Path, socket: &std::path::Path) -> String {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(75);
    loop {
        let out = run_nn_admin_at(
            nn,
            &["status", "--socket", socket.to_str().unwrap(), "--json"],
        );
        let last = String::from_utf8_lossy(&out.stdout).into_owned();
        if last.contains("\"network_isolation_engaged\":true") {
            return last;
        }
        assert!(
            last.contains("\"posture\":\"Combat\""),
            "posture left COMBAT while waiting for isolation: {last}"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "ladder never reached ISOLATE within 75s; last status: {last}"
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

#[test]
fn e2e_force_combat_then_unlock_via_cli() {
    // Belt-and-braces: the unlock step at the end of this test
    // already drives `NetworkIsolator::release`, but if any
    // assertion before that step fails (or the test panics),
    // the chain would be left attached and the host loses
    // outbound networking. The RAII guard runs unconditionally
    // on scope exit.
    let _eni = EniIptablesGuard::install();
    let dir = tempfile::tempdir().expect("tempdir");
    let priv_key = init_admin_keypair(dir.path());
    // External audit NN-AUD-083: a second key holding only `force-posture`.
    let (force_only_key, _) = init_admin_keypair_with_roles(
        Path::new(nn_admin_bin()),
        dir.path(),
        &dir.path().join("admin.pub"),
        "force_only",
        "force-posture",
    );
    let (_guard, handles) = spawn_agent(dir.path());
    let nn = handles.nn_admin_path.as_path();
    let socket = handles.socket.as_path();

    // Drive the agent into COMBAT via the debug feature.
    let out = run_nn_admin_at(
        nn,
        &[
            "debug",
            "force-posture",
            "combat",
            "--socket",
            socket.to_str().unwrap(),
        ],
    );
    assert!(
        out.status.success(),
        "debug force-posture failed: stderr={:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Status mirrors the forced state. COMBAT entry arms the graduated
    // ladder (INVESTIGATE, network UP); with no attributed offender the
    // ladder escalates to ISOLATE on its own once the investigate
    // window (30 s default) elapses — wait for that instead of
    // expecting isolation on entry (lab guest, 2026-10-08).
    let body = wait_for_isolation(nn, socket);
    assert!(
        body.contains("\"posture\":\"Combat\""),
        "status body: {body}"
    );

    // iptables now carries our DROP rules.
    let rules = list_combat_chain_rules();
    let joined = rules.join("\n");
    assert!(
        joined.contains("-j DROP"),
        "expected DROP rule in NORTHNARROW_COMBAT, got: {joined}"
    );
    // Loopback carve-out: the chain is TERMINAL since combat-rules.v4
    // switched lo from RETURN to ACCEPT (see configs/combat-rules.v4
    // header); accept either form so the test tracks the ruleset.
    assert!(
        [
            "-i lo -j ACCEPT",
            "-o lo -j ACCEPT",
            "-i lo -j RETURN",
            "-o lo -j RETURN"
        ]
        .iter()
        .any(|r| joined.contains(r)),
        "expected loopback ACCEPT/RETURN in chain, got: {joined}"
    );

    // External audit NN-AUD-083: the `force-posture`-only key cannot leave
    // COMBAT (it used to release the containment like `unlock`): role
    // denied (exit 7), posture and DROP chain unchanged.
    let out = run_nn_admin_at(
        nn,
        &[
            "force-posture",
            "engaged",
            "--key",
            force_only_key.to_str().unwrap(),
            "--socket",
            socket.to_str().unwrap(),
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(7),
        "force-posture out of COMBAT without unlock must be role-denied: stderr={:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        list_combat_chain_rules().join("\n").contains("-j DROP"),
        "the isolation chain must stay in place"
    );
    let out = run_nn_admin_at(
        nn,
        &["status", "--socket", socket.to_str().unwrap(), "--json"],
    );
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(
        body.contains("\"posture\":\"Combat\""),
        "status body: {body}"
    );

    // Sign + submit; should win.
    let out = run_nn_admin_at(
        nn,
        &[
            "unlock",
            "--key",
            priv_key.to_str().unwrap(),
            "--socket",
            socket.to_str().unwrap(),
        ],
    );
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
    let out = run_nn_admin_at(
        nn,
        &["status", "--socket", socket.to_str().unwrap(), "--json"],
    );
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
    // The test drives Combat then attempts a wrong-key unlock
    // (which must fail). The chain stays installed for the
    // duration; the recovery unlock at the bottom cleans it,
    // but the RAII guard is here for panic-safety in case any
    // earlier assertion fires.
    let _eni = EniIptablesGuard::install();
    let dir = tempfile::tempdir().expect("tempdir");

    // Install pubkey A into admin.pub.
    let _correct_priv = init_admin_keypair(dir.path());

    // Generate keypair B at a different location; B's pubkey is
    // NOT in admin.pub. Use a clean second tempdir as a "wrong key
    // shop" so B's init doesn't also append to the real admin.pub.
    let other = tempfile::tempdir().expect("tempdir2");
    let other_priv = init_admin_keypair(other.path());

    let (_guard, handles) = spawn_agent(dir.path());
    let nn = handles.nn_admin_path.as_path();
    let socket = handles.socket.as_path();

    // Force Combat to make the test meaningful.
    let out = run_nn_admin_at(
        nn,
        &[
            "debug",
            "force-posture",
            "combat",
            "--socket",
            socket.to_str().unwrap(),
        ],
    );
    assert!(out.status.success());

    // Unlock with the wrong private key.
    let out = run_nn_admin_at(
        nn,
        &[
            "unlock",
            "--key",
            other_priv.to_str().unwrap(),
            "--socket",
            socket.to_str().unwrap(),
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected InvalidSignature exit code 2, stderr={:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Posture still Combat; the ladder keeps running and reaches
    // ISOLATE after the investigate window — a rejected unlock must not
    // have released it.
    let out = run_nn_admin_at(
        nn,
        &["status", "--socket", socket.to_str().unwrap(), "--json"],
    );
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(
        body.contains("\"posture\":\"Combat\""),
        "status body: {body}"
    );
    let body = wait_for_isolation(nn, socket);
    assert!(
        body.contains("\"posture\":\"Combat\""),
        "status body: {body}"
    );

    // Cleanup: tear down the chain via correct unlock so we don't
    // leave the test host network-isolated if the test runner aborts.
    let _ = run_nn_admin_at(
        nn,
        &[
            "unlock",
            "--key",
            _correct_priv.to_str().unwrap(),
            "--socket",
            socket.to_str().unwrap(),
        ],
    );
}

/// External audit NN-AUD-079: failed signatures count per connection,
/// and every nn-admin call is a connection of its own — wrong-key unlocks
/// never rate-limit a later call, nor the right key. (The agent-wide
/// five-minute window this test could not exercise is gone.) No COMBAT is
/// needed: an unlock outside COMBAT answers success.
#[test]
fn e2e_failures_on_other_connections_do_not_rate_limit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let correct_priv = init_admin_keypair(dir.path());
    let other = tempfile::tempdir().expect("tempdir2");
    let other_priv = init_admin_keypair(other.path());
    let (_guard, handles) = spawn_agent(dir.path());
    let nn = handles.nn_admin_path.as_path();
    let socket = handles.socket.as_path();

    for attempt in 1..=4 {
        let out = run_nn_admin_at(
            nn,
            &[
                "unlock",
                "--key",
                other_priv.to_str().unwrap(),
                "--socket",
                socket.to_str().unwrap(),
            ],
        );
        assert_eq!(
            out.status.code(),
            Some(2),
            "wrong-key unlock #{attempt} must be InvalidSignature (2), never RateLimited (4): \
             stderr={:?}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let out = run_nn_admin_at(
        nn,
        &[
            "unlock",
            "--key",
            correct_priv.to_str().unwrap(),
            "--socket",
            socket.to_str().unwrap(),
        ],
    );
    assert!(
        out.status.success(),
        "the right key is not rate-limited: code={:?} stderr={:?}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn e2e_status_no_admin_action_initially() {
    let dir = tempfile::tempdir().expect("tempdir");
    let _priv = init_admin_keypair(dir.path());
    let (_guard, handles) = spawn_agent(dir.path());
    let nn = handles.nn_admin_path.as_path();
    let socket = handles.socket.as_path();

    let out = run_nn_admin_at(
        nn,
        &["status", "--socket", socket.to_str().unwrap(), "--json"],
    );
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

// ── PHASE_D_003 — Tappa 8 A15 privileged round-trip tests ───────────
//
// Three integration tests proving the Tappa 8 sub-sprint B
// signed-admin pipeline is operational end-to-end:
//   1. Signed shutdown round-trip (A7 + B5 wiring).
//   2. Rotate-keys round-trip (A13 + B3 atomic rewrite + reload).
//   3. Audit-verify e2e (B1 chain + B5 dispatch wiring).
//
// All three use a NEW agent-spawn helper `spawn_agent_b5` that
// passes per-test tempdir paths for the three B5-era state files
// the upstream `spawn_agent` doesn't configure (signing key,
// audit log, shutdown marker). This avoids mutating the host's
// `/etc/northnarrow/` and `/run/northnarrow/` state.
//
// R009 (root-exec-from-/home/) is not tripped because none of
// these tests trigger malicious-looking activity — they only
// drive admin operations through the documented CLI surface.

const NN_ADMIN_OP_TIMEOUT: Duration = Duration::from_secs(10);

/// PHASE_D_003 R009 avoidance: sudo-install a binary under
/// `/usr/local/bin/<basename>-e2etest-<ts>-<pid>` so the agent's
/// `R009_RootExecFromUserPath` rule (which kills any root spawn
/// originating from `/home/`, `/tmp/`, `/var/tmp/`) doesn't
/// match. Ported from `watchdog/tests/privileged_e2e.rs`
/// PHASE_D_001 W8 commit; same pattern, same RAII cleanup.
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

/// PHASE_D_003 agent-spawn helper: like `spawn_agent` but threads
/// the three B5-era CLI flags (`--signing-key-file`,
/// `--audit-log-file`, `--shutdown-marker-file`) plus an
/// `--agent-id-file` per-test override so the agent's audit /
/// rotate-keys / shutdown paths all stay scoped to the tempdir.
/// Returns the running child + every per-test path the caller
/// might need to inspect.
struct B5Paths {
    socket: PathBuf,
    admin_pub: PathBuf,
    agent_id_file: PathBuf,
    signing_key_file: PathBuf,
    audit_log_file: PathBuf,
    shutdown_marker_file: PathBuf,
    /// PHASE_D_003 R009 avoidance: keep the InstalledBin RAII
    /// handles alive for the test's lifetime so Drop cleans
    /// `/usr/local/bin/*-e2etest-*` on exit. The path string
    /// inside is what subprocesses invoke as `nn-admin`.
    nn_admin_path: PathBuf,
    _installed_agent: InstalledBin,
    _installed_admin: InstalledBin,
}

/// PHASE_D_003 fixture-style spawn: install agent + nn-admin
/// under /usr/local/bin/ (R009 avoidance), then spawn the
/// installed-path agent with per-test tempdir flags. Returns
/// the running child + every path the caller might need.
/// AgentGuard's Drop SIGQUITs the agent; B5Paths's InstalledBin
/// Drops remove the /usr/local/bin/ copies.
///
/// **Two-step pattern for tests that need to mint admin keys
/// AFTER agent boot:** call [`install_priv_bins`] FIRST (returns
/// the InstalledBin handles + the nn-admin path), build the
/// initial admin.pub using that nn-admin path, then call
/// [`spawn_agent_b5_with_installs`] passing the moved handles.
/// `spawn_agent_b5` is the convenience all-in-one for tests
/// that build the admin.pub BEFORE agent boot only.
#[allow(dead_code)]
fn spawn_agent_b5(tempdir: &Path) -> (AgentGuard, B5Paths) {
    let (installed_agent, installed_admin) = install_priv_bins();
    spawn_agent_b5_with_installs(tempdir, installed_agent, installed_admin)
}

/// Two-step pattern step 1: install agent + nn-admin to
/// /usr/local/bin/ and return the RAII handles. Lets tests
/// use the installed nn-admin for pre-spawn init calls (R009
/// doesn't fire pre-spawn but the test code path stays
/// uniform — once installed, every nn-admin call uses the same
/// path whether the agent is up or not).
fn install_priv_bins() -> (InstalledBin, InstalledBin) {
    let installed_agent = install_to_priv_bin(Path::new(agent_bin()));
    let installed_admin = install_to_priv_bin(Path::new(nn_admin_bin()));
    (installed_agent, installed_admin)
}

/// Two-step pattern step 2: spawn the agent using the already-
/// installed binaries.
fn spawn_agent_b5_with_installs(
    tempdir: &Path,
    installed_agent: InstalledBin,
    installed_admin: InstalledBin,
) -> (AgentGuard, B5Paths) {
    let paths = B5Paths {
        socket: tempdir.join("admin.sock"),
        admin_pub: tempdir.join("admin.pub"),
        agent_id_file: tempdir.join("agent_id"),
        signing_key_file: tempdir.join("agent.sig.key"),
        audit_log_file: tempdir.join("audit.log"),
        shutdown_marker_file: tempdir.join("agent.shutdown_authorised"),
        nn_admin_path: installed_admin.path.clone(),
        _installed_agent: installed_agent,
        _installed_admin: installed_admin,
    };
    let rules = tempdir.join("combat-rules.v4");
    std::fs::copy(combat_rules_path(), &rules).expect("copy combat rules");

    // Spawn the installed (root-owned, /usr/local/bin/) agent
    // under sudo so it inherits root privileges + bypasses
    // R009. AgentGuard's SIGQUIT-on-drop still works against
    // the root subprocess because the kill comes from the test
    // process which is also root via the outer sudo.
    common::require_bpftool();
    let child = Command::new("sudo")
        .arg(&paths._installed_agent.path)
        .arg("--combat-rules")
        .arg(&rules)
        .arg("--admin-pub")
        .arg(&paths.admin_pub)
        .arg("--admin-socket")
        .arg(&paths.socket)
        .arg("--agent-id-file")
        .arg(&paths.agent_id_file)
        .arg("--signing-key-file")
        .arg(&paths.signing_key_file)
        .arg("--audit-log-file")
        .arg(&paths.audit_log_file)
        .arg("--shutdown-marker-file")
        .arg(&paths.shutdown_marker_file)
        .arg("--no-ade")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn northnarrow-agent (PHASE_D_003)");
    let guard = AgentGuard(Some(child));
    wait_for_socket(&paths.socket);
    (guard, paths)
}

/// Initialise an admin keypair with the explicit roles list
/// the rotate-keys + shutdown tests need. Mirrors the existing
/// `init_admin_keypair` helper but writes a `<hex> <roles>`
/// line (vs the bare-pubkey default `init` emits) so the
/// agent's per-key role allowlist accepts the test operations.
///
/// `nn_admin_path` is the binary to invoke — either the
/// cargo target path (when called BEFORE agent spawn) or the
/// `/usr/local/bin/` install (when called AFTER, to dodge
/// the agent's R009_RootExecFromUserPath rule).
fn init_admin_keypair_with_roles(
    nn_admin_path: &Path,
    tempdir: &Path,
    pub_path: &Path,
    label: &str,
    roles: &str,
) -> (PathBuf, String) {
    let priv_path = tempdir.join(format!("{label}.priv"));
    let tmp_pub = tempdir.join(format!("{label}.pub.tmp"));
    let status = Command::new(nn_admin_path)
        .arg("init")
        .arg("--priv-out")
        .arg(&priv_path)
        .arg("--pub-append")
        .arg(&tmp_pub)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("spawn nn-admin init");
    assert!(status.success(), "nn-admin init failed for {label}");
    // `nn-admin init --pub-append` writes TWO lines: a `#`
    // comment-line preamble + the raw 64-hex pubkey. Pick the
    // first non-`#` non-empty line as the hex; reject if its
    // shape doesn't match (defensive — surfaces a clear test
    // failure if the writer format changes).
    let tmp_body = std::fs::read_to_string(&tmp_pub).expect("read tmp pubkey");
    let hex = tmp_body
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .expect("init pub file has no hex line");
    assert_eq!(
        hex.len(),
        64,
        "init pub file's hex line is {} chars (expected 64): {hex:?}",
        hex.len()
    );
    // Append `<hex> <roles>\n` to the real admin.pub.
    use std::io::Write;
    let mut pub_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(pub_path)
        .expect("open admin.pub for append");
    writeln!(pub_file, "{hex} {roles}").expect("append pubkey");
    let _ = std::fs::remove_file(&tmp_pub);
    (priv_path, hex.to_string())
}

/// Unused in B5 tests but kept as a primitive for future
/// PHASE_D_004 work that wants to assert which key fingerprint
/// an audit row carries (B5 ships with empty key_fp by design).
#[allow(dead_code)]
fn fingerprint_of_admin_pub(nn_admin_path: &Path, pub_path: &Path) -> String {
    let out = Command::new(nn_admin_path)
        .arg("verify-keys")
        .arg("--path")
        .arg(pub_path)
        .output()
        .expect("spawn nn-admin verify-keys");
    assert!(
        out.status.success(),
        "verify-keys failed: stderr={:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body = String::from_utf8_lossy(&out.stdout);
    body.lines()
        .filter_map(|l| {
            let t = l.trim();
            if t.len() == 8 && t.chars().all(|c| c.is_ascii_hexdigit()) {
                Some(t.to_string())
            } else {
                None
            }
        })
        .next_back()
        .expect("at least one fingerprint in verify-keys output")
}

/// Wait until the agent's shutdown_authorised marker exists or
/// the deadline elapses. Returns Some(body) on success, None
/// on timeout.
fn wait_for_marker(path: &Path, deadline: Duration) -> Option<String> {
    let until = Instant::now() + deadline;
    while Instant::now() < until {
        if let Ok(s) = std::fs::read_to_string(path) {
            if !s.is_empty() {
                return Some(s);
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

/// PHASE_D_003 test #1 — signed shutdown round-trip (design
/// §10.3 + B5 wiring). Spawns the agent, generates a 2-key
/// quorum with `shutdown` role on both, submits a signed
/// ShutdownRequest, asserts the shutdown-authorised marker
/// lands on disk AND a "shutdown" audit row is appended.
///
/// Does NOT wait for agent process exit — the in-process
/// shutdown signal is the watchdog's responsibility to honour;
/// here we verify the agent-side contract (marker written +
/// audit row emitted) only. AgentGuard's drop SIGQUITs the
/// agent at teardown either way.
#[test]
fn shutdown_signed_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (installed_agent, installed_admin) = install_priv_bins();
    let nn_admin = installed_admin.path.clone();

    // Pre-create the admin.pub file with two keys carrying the
    // `shutdown` role + agent_id so AdminAuth::load_with_agent_id
    // succeeds. `unlock,shutdown` covers both ops.
    std::fs::write(dir.path().join("admin.pub"), "").expect("touch admin.pub");
    let (priv_a, _) = init_admin_keypair_with_roles(
        &nn_admin,
        dir.path(),
        &dir.path().join("admin.pub"),
        "admin_a",
        "unlock,shutdown",
    );
    let (priv_b, _) = init_admin_keypair_with_roles(
        &nn_admin,
        dir.path(),
        &dir.path().join("admin.pub"),
        "admin_b",
        "unlock,shutdown",
    );

    let (_guard, paths) =
        spawn_agent_b5_with_installs(dir.path(), installed_agent, installed_admin);

    // Submit the signed shutdown.
    let out = Command::new(&paths.nn_admin_path)
        .args([
            "shutdown",
            "--key",
            priv_a.to_str().unwrap(),
            "--cosign-key",
            priv_b.to_str().unwrap(),
            "--agent-id-file",
            paths.agent_id_file.to_str().unwrap(),
            "--socket",
            paths.socket.to_str().unwrap(),
            "--grace-secs",
            "10",
        ])
        .output()
        .expect("spawn nn-admin shutdown");
    assert!(
        out.status.success(),
        "shutdown failed: code={:?} stderr={:?}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    // Marker lands on disk within the grace window.
    let marker = wait_for_marker(&paths.shutdown_marker_file, NN_ADMIN_OP_TIMEOUT)
        .expect("shutdown_authorised marker never appeared");
    // External audit TST-003: the marker carries the quorum the agent
    // verified, and verifies against the same admin.pub and agent_id —
    // what the watchdog checks before it stands down.
    let parsed = ::common::shutdown_marker::ShutdownMarker::parse(&marker)
        .unwrap_or_else(|e| panic!("marker body unexpected ({e}): {marker}"));
    let keys = ::common::admin_quorum::parse_admin_pub(
        &std::fs::read_to_string(&paths.admin_pub).expect("admin.pub"),
    )
    .expect("admin.pub parses");
    let agent_id = ::common::shutdown_marker::parse_agent_id(
        &std::fs::read_to_string(&paths.agent_id_file).expect("agent_id"),
    )
    .expect("agent_id parses");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let exp = ::common::shutdown_marker::Expectation {
        keys: &keys,
        agent_id,
        agent_pid: parsed.agent_pid,
        agent_started: None,
        now,
    };
    ::common::shutdown_marker::verify(&parsed, &exp, |_| false)
        .unwrap_or_else(|e| panic!("the watchdog would refuse the agent's marker: {e}"));

    // Audit row emitted for the op (B5 wiring).
    let audit_body =
        std::fs::read_to_string(&paths.audit_log_file).expect("audit log readable post-shutdown");
    let lines: Vec<&str> = audit_body.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        !lines.is_empty(),
        "audit log should have ≥ 1 entry after shutdown"
    );
    // The admin op is the last entry before the agent's own `agent_stop`
    // (written when the event loop ends, reason `admin_shutdown`); the test
    // may read the file before or after that final write.
    let shutdown_idx = lines
        .iter()
        .rposition(|l| l.contains("\"op\":\"shutdown\""))
        .unwrap_or_else(|| panic!("no op=shutdown entry in the audit log: {audit_body}"));
    let last = lines[shutdown_idx];
    assert!(
        last.contains("\"result\":\"success\""),
        "op=shutdown entry should be result=success: {last}"
    );
    for after in &lines[shutdown_idx + 1..] {
        assert!(
            after.contains("\"op\":\"agent_stop\"") && after.contains("\"reason\":\"admin_shutdown\""),
            "only the agent's own agent_stop (reason admin_shutdown) may follow op=shutdown: {after}"
        );
    }
    let _ = (priv_a, priv_b);
}

/// PHASE_D_003 test #2: rotate-keys round-trip per design §7.2
/// plus B3 atomic rewrite plus B5 audit. Spawns the agent with
/// two rotate-keys-role keys, mints a fresh third key, submits
/// RotateKeysAdd, then asserts: admin.pub now has three lines
/// (atomic rewrite worked), the new key can immediately
/// authorise an unlock (hot-reload via RwLock-backed pub_keys
/// worked), and an audit row records the op=rotate_keys_add
/// success.
#[test]
fn rotate_keys_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (installed_agent, installed_admin) = install_priv_bins();
    let nn_admin = installed_admin.path.clone();

    std::fs::write(dir.path().join("admin.pub"), "").expect("touch admin.pub");
    let (priv_a, _) = init_admin_keypair_with_roles(
        &nn_admin,
        dir.path(),
        &dir.path().join("admin.pub"),
        "admin_a",
        "unlock,rotate-keys",
    );
    let (priv_b, _) = init_admin_keypair_with_roles(
        &nn_admin,
        dir.path(),
        &dir.path().join("admin.pub"),
        "admin_b",
        "unlock,rotate-keys",
    );

    let (_guard, paths) =
        spawn_agent_b5_with_installs(dir.path(), installed_agent, installed_admin);

    // Mint a fresh keypair OUTSIDE the agent's admin.pub so we
    // can inject its pubkey via rotate-keys-add (the production
    // path the operator workflow uses).
    let scratch = tempfile::tempdir().expect("scratch tempdir");
    let (new_priv, new_pub_hex) = init_admin_keypair_with_roles(
        &nn_admin,
        scratch.path(),
        &scratch.path().join("scratch.pub"),
        "new_key",
        "unlock",
    );

    // Submit rotate-keys add.
    let out = Command::new(&paths.nn_admin_path)
        .args([
            "rotate-keys",
            "add",
            "--new-pubkey",
            &new_pub_hex,
            "--new-roles",
            "unlock",
            "--key",
            priv_a.to_str().unwrap(),
            "--cosign-key",
            priv_b.to_str().unwrap(),
            "--agent-id-file",
            paths.agent_id_file.to_str().unwrap(),
            "--socket",
            paths.socket.to_str().unwrap(),
        ])
        .output()
        .expect("spawn nn-admin rotate-keys add");
    assert!(
        out.status.success(),
        "rotate-keys add failed: code={:?} stderr={:?}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    // (a) admin.pub now has THREE lines.
    let pub_body =
        std::fs::read_to_string(&paths.admin_pub).expect("admin.pub readable post-rewrite");
    let line_count = pub_body
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .count();
    assert_eq!(line_count, 3, "admin.pub should have 3 lines: {pub_body}");
    assert!(
        pub_body.contains(&new_pub_hex),
        "new pubkey must appear in admin.pub: {pub_body}"
    );

    // (b) hot-reload: the new key can immediately authorise an
    // unlock (no agent restart). Force COMBAT first so unlock
    // has something to release.
    let _ = Command::new(&paths.nn_admin_path)
        .args([
            "debug",
            "force-posture",
            "combat",
            "--socket",
            paths.socket.to_str().unwrap(),
        ])
        .output();
    let out = Command::new(&paths.nn_admin_path)
        .args([
            "unlock",
            "--key",
            new_priv.to_str().unwrap(),
            "--socket",
            paths.socket.to_str().unwrap(),
        ])
        .output()
        .expect("spawn nn-admin unlock with new key");
    assert!(
        out.status.success(),
        "unlock with rotated-in key failed: code={:?} stderr={:?}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    // (c) audit row records the rotate_keys_add success.
    let audit_body = std::fs::read_to_string(&paths.audit_log_file).expect("audit log readable");
    assert!(
        audit_body.contains("\"op\":\"rotate_keys_add\""),
        "audit log should have a rotate_keys_add entry: {audit_body}"
    );
    assert!(
        audit_body.contains("\"op\":\"unlock\""),
        "audit log should also have the unlock entry: {audit_body}"
    );

    // External audit NN-AUD-084: the two `unlock,rotate-keys` signers
    // cannot mint a key with a role they lack (`all`, `shutdown`): role
    // denied (exit 7), admin.pub unchanged.
    for roles in ["all", "unlock,shutdown"] {
        let scratch = tempfile::tempdir().expect("scratch tempdir");
        let (_, hex) = init_admin_keypair_with_roles(
            &nn_admin,
            scratch.path(),
            &scratch.path().join("scratch.pub"),
            "too_strong",
            "unlock",
        );
        let out = Command::new(&paths.nn_admin_path)
            .args([
                "rotate-keys",
                "add",
                "--new-pubkey",
                &hex,
                "--new-roles",
                roles,
                "--key",
                priv_a.to_str().unwrap(),
                "--cosign-key",
                priv_b.to_str().unwrap(),
                "--agent-id-file",
                paths.agent_id_file.to_str().unwrap(),
                "--socket",
                paths.socket.to_str().unwrap(),
            ])
            .output()
            .expect("spawn nn-admin rotate-keys add");
        assert_eq!(
            out.status.code(),
            Some(7),
            "rotate-keys add --new-roles {roles} must be role-denied: stderr={:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        let body = std::fs::read_to_string(&paths.admin_pub).expect("admin.pub readable");
        assert!(
            !body.contains(&hex),
            "admin.pub must not gain {hex}: {body}"
        );
    }
}

/// PHASE_D_003 test #3 — audit-verify e2e (design §9 + B2
/// `nn-admin audit verify` + B5 dispatch wiring). Drive a mix
/// of admin ops (1 unlock success + 1 unlock failure +
/// 1 rotate-keys add success) so the audit log accumulates
/// 3 entries with both success and failure rows, then run
/// `nn-admin audit verify --from <log> --agent-sig-key <key>`
/// and assert it reports an intact chain with exactly 3
/// entries.
#[test]
fn audit_verify_e2e() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (installed_agent, installed_admin) = install_priv_bins();
    let nn_admin = installed_admin.path.clone();

    std::fs::write(dir.path().join("admin.pub"), "").expect("touch admin.pub");
    let (priv_a, _) = init_admin_keypair_with_roles(
        &nn_admin,
        dir.path(),
        &dir.path().join("admin.pub"),
        "admin_a",
        "unlock,rotate-keys",
    );
    let (priv_b, _) = init_admin_keypair_with_roles(
        &nn_admin,
        dir.path(),
        &dir.path().join("admin.pub"),
        "admin_b",
        "unlock,rotate-keys",
    );

    let (_guard, paths) =
        spawn_agent_b5_with_installs(dir.path(), installed_agent, installed_admin);

    // Op 1: successful unlock (no Combat to release → server
    // returns Success idempotently per the existing
    // verify_unlock contract).
    let _ = Command::new(&paths.nn_admin_path)
        .args([
            "unlock",
            "--key",
            priv_a.to_str().unwrap(),
            "--socket",
            paths.socket.to_str().unwrap(),
        ])
        .output()
        .expect("spawn nn-admin unlock");

    // Op 2: failed unlock (wrong-key — a fresh keypair never
    // installed into admin.pub).
    let scratch = tempfile::tempdir().expect("scratch");
    let (wrong_priv, _) = init_admin_keypair_with_roles(
        &nn_admin,
        scratch.path(),
        &scratch.path().join("scratch.pub"),
        "wrong",
        "unlock",
    );
    let _ = Command::new(&paths.nn_admin_path)
        .args([
            "unlock",
            "--key",
            wrong_priv.to_str().unwrap(),
            "--socket",
            paths.socket.to_str().unwrap(),
        ])
        .output()
        .expect("spawn nn-admin unlock wrong-key");

    // Op 3: successful rotate-keys add.
    let third_scratch = tempfile::tempdir().expect("scratch3");
    let (_third_priv, third_pub_hex) = init_admin_keypair_with_roles(
        &nn_admin,
        third_scratch.path(),
        &third_scratch.path().join("scratch.pub"),
        "third",
        "unlock",
    );
    let _ = Command::new(&paths.nn_admin_path)
        .args([
            "rotate-keys",
            "add",
            "--new-pubkey",
            &third_pub_hex,
            "--new-roles",
            "unlock",
            "--key",
            priv_a.to_str().unwrap(),
            "--cosign-key",
            priv_b.to_str().unwrap(),
            "--agent-id-file",
            paths.agent_id_file.to_str().unwrap(),
            "--socket",
            paths.socket.to_str().unwrap(),
        ])
        .output()
        .expect("spawn nn-admin rotate-keys add");

    // The audit log holds the boot-time `agent_boot` write probe
    // (etc-readonly-audit-1), unlock success, unlock failure and
    // rotate_keys_add success — and whatever the agent attests about the
    // host it found (`integrity_drift`, external audit MAIN-003: on a lab
    // guest, the installed agent's FIM baseline, signed by another key).
    // Verify chain integrity via the CLI.
    let audit_body = std::fs::read_to_string(&paths.audit_log_file).expect("audit log readable");
    let entries: Vec<serde_json::Value> = audit_body
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).expect("audit line is JSON"))
        .collect();
    let ops: Vec<(String, String)> = entries
        .iter()
        .filter(|e| e["op"] != "integrity_drift")
        .map(|e| {
            (
                e["op"].as_str().unwrap_or_default().to_string(),
                e["result"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let ops: Vec<(&str, &str)> = ops.iter().map(|(o, r)| (o.as_str(), r.as_str())).collect();
    assert_eq!(
        ops,
        [
            ("agent_boot", "success"),
            ("unlock", "success"),
            ("unlock", "failure: invalid_signature"),
            ("rotate_keys_add", "success"),
        ],
        "the boot probe, then the three admin ops: {audit_body}"
    );

    let out = Command::new(&paths.nn_admin_path)
        .args([
            "audit",
            "verify",
            "--from",
            paths.audit_log_file.to_str().unwrap(),
            "--agent-sig-key",
            paths.signing_key_file.to_str().unwrap(),
        ])
        .output()
        .expect("spawn nn-admin audit verify");
    assert!(
        out.status.success(),
        "audit verify reported broken chain: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(
        body.contains(&format!("{} entries", entries.len())) && body.contains("intact"),
        "audit verify output unexpected: {body}"
    );
}

/// External audit SNS-001 (NN-AUD-184): a dead ring pump is noticed. The
/// `debug-trigger` hook aborts the `fs_protect` pump; within two liveness
/// checks (5 s each) the agent writes a signed `subsystem_degraded` naming
/// the pump and a signed `agent_stop` (`sensor_pump_exited`), and exits
/// non-zero — under systemd the watchdog then respawns it.
#[cfg(feature = "debug-trigger")]
#[test]
fn dead_sensor_pump_stops_the_agent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (installed_agent, installed_admin) = install_priv_bins();
    let nn_admin = installed_admin.path.clone();
    std::fs::write(dir.path().join("admin.pub"), "").expect("touch admin.pub");
    let _ = init_admin_keypair_with_roles(
        &nn_admin,
        dir.path(),
        &dir.path().join("admin.pub"),
        "admin_a",
        "unlock",
    );
    let (mut guard, paths) =
        spawn_agent_b5_with_installs(dir.path(), installed_agent, installed_admin);

    std::fs::write(dir.path().join("debug-abort-pump"), "fs_protect\n")
        .expect("write the abort trigger");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        let child = guard.0.as_mut().expect("agent child");
        match child.try_wait().expect("try_wait") {
            Some(st) => break st,
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            None => panic!("the agent kept running 30 s after its fs_protect pump was aborted"),
        }
    };
    assert!(
        !status.success(),
        "a dead pump must end the agent with a failure: {status}"
    );

    let log = std::fs::read_to_string(&paths.audit_log_file).expect("read audit log");
    let degraded = log
        .lines()
        .find(|l| l.contains("subsystem_degraded") && l.contains("sensor pump exited"))
        .unwrap_or_else(|| panic!("no signed subsystem_degraded for the pump:\n{log}"));
    assert!(degraded.contains("fs_protect"), "{degraded}");
    assert!(
        log.lines()
            .any(|l| l.contains("\"agent_stop\"") && l.contains("sensor_pump_exited")),
        "no signed agent_stop sensor_pump_exited:\n{log}"
    );
}

// ── External audit TST-001 / TST-010 (lab PR 153): the guard in enforce ──
//
// Every other fixture stops its agent by evicting it from PROTECTED_PIDS
// with bpftool (`common::quit_agent`), which works only because a
// `debug-trigger` build runs the BPF map guard in observe mode. This test
// forces enforce (`NN_BPF_DEFENSE_ENFORCE=1`, the production default) and
// asserts what root gets: the eviction and the kill refused, the fixtures'
// teardown failing and saying why, the signed shutdown as the way out.
// `--detect-only`: the refused attempts are tamper attempts and put the
// agent in COMBAT, and no response may act on the test runner (lab PR
// 153: a COMBAT agent killed the runner, then the next test binaries).
//
// The guard outlives its agent (pinned link) and goes on enforcing. The
// next fixture's agent is another installed copy, another inode, so it is
// foreign to the guard and would be refused its own registration. Drop
// therefore starts the same installed binary once more without the
// variable — the successor the guard admits in its first minute — which
// re-arms the guard in observe mode, and stops it.

#[cfg(feature = "debug-trigger")]
const GUARD_STOP_TIMEOUT: Duration = Duration::from_secs(20);
#[cfg(feature = "debug-trigger")]
const GUARD_LOG_TIMEOUT: Duration = Duration::from_secs(10);

/// `s` without ANSI escape sequences (the agent colours its log unless
/// `NO_COLOR` is set).
#[cfg(feature = "debug-trigger")]
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for d in chars.by_ref() {
                if ('@'..='~').contains(&d) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(feature = "debug-trigger")]
fn read_agent_log(path: &Path) -> String {
    strip_ansi(&std::fs::read_to_string(path).unwrap_or_default())
}

#[cfg(feature = "debug-trigger")]
fn log_tail(path: &Path) -> String {
    let log = read_agent_log(path);
    let lines: Vec<&str> = log.lines().collect();
    format!(
        "--- {} (tail) ---\n{}",
        path.display(),
        lines[lines.len().saturating_sub(40)..].join("\n")
    )
}

/// First line of the agent log holding every needle, waiting up to `timeout`.
#[cfg(feature = "debug-trigger")]
fn wait_for_log_line(path: &Path, needles: &[&str], timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(l) = read_agent_log(path)
            .lines()
            .find(|l| needles.iter().all(|n| l.contains(n)))
        {
            return Some(l.to_string());
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// One agent process of [`GuardFixture`].
#[cfg(feature = "debug-trigger")]
struct GuardRun {
    name: &'static str,
    child: Child,
    socket: PathBuf,
    pid_file: PathBuf,
    log: PathBuf,
}

/// Wait until the agent's pid file and socket exist; returns its pid. The
/// pid file is written once every hook is attached and the pid is in
/// PROTECTED_PIDS (`--pid-file`, main.rs).
#[cfg(feature = "debug-trigger")]
fn wait_ready(run: &mut GuardRun) -> Result<u32, String> {
    let deadline = Instant::now() + SOCKET_POLL_TIMEOUT;
    loop {
        if run.pid_file.exists() && run.socket.exists() {
            let body = std::fs::read_to_string(&run.pid_file)
                .map_err(|e| format!("reading {}: {e}", run.pid_file.display()))?;
            return body
                .trim()
                .parse()
                .map_err(|e| format!("pid file {body:?}: {e}"));
        }
        match run.child.try_wait() {
            Ok(Some(st)) => {
                return Err(format!(
                    "the {} agent exited at boot ({st})\n{}",
                    run.name,
                    log_tail(&run.log)
                ))
            }
            Ok(None) => {}
            Err(e) => return Err(format!("try_wait on the {} agent: {e}", run.name)),
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "the {} agent was not ready within {SOCKET_POLL_TIMEOUT:?}\n{}",
                run.name,
                log_tail(&run.log)
            ));
        }
        std::thread::sleep(SOCKET_POLL_INTERVAL);
    }
}

#[cfg(feature = "debug-trigger")]
struct GuardFixture {
    dir: tempfile::TempDir,
    nn_admin: PathBuf,
    agent: PathBuf,
    admin_pub: PathBuf,
    agent_id_file: PathBuf,
    key_a: PathBuf,
    key_b: PathBuf,
    enforce_run: Option<GuardRun>,
    // Removed only after `drop` ran: the restore run needs this binary.
    _installed_agent: InstalledBin,
    _installed_admin: InstalledBin,
}

#[cfg(feature = "debug-trigger")]
impl GuardFixture {
    /// Installed agent + nn-admin, two keys with the `shutdown` role.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let (installed_agent, installed_admin) = install_priv_bins();
        let nn_admin = installed_admin.path.clone();
        let admin_pub = dir.path().join("admin.pub");
        std::fs::write(&admin_pub, "").expect("touch admin.pub");
        let (key_a, _) = init_admin_keypair_with_roles(
            &nn_admin,
            dir.path(),
            &admin_pub,
            "admin_a",
            "unlock,shutdown",
        );
        let (key_b, _) = init_admin_keypair_with_roles(
            &nn_admin,
            dir.path(),
            &admin_pub,
            "admin_b",
            "unlock,shutdown",
        );
        std::fs::copy(combat_rules_path(), dir.path().join("combat-rules.v4"))
            .expect("copy combat rules");
        Self {
            agent_id_file: dir.path().join("agent_id"),
            agent: installed_agent.path.clone(),
            dir,
            nn_admin,
            admin_pub,
            key_a,
            key_b,
            enforce_run: None,
            _installed_agent: installed_agent,
            _installed_admin: installed_admin,
        }
    }

    /// Start the installed agent; `enforce` forces the guard's deny mode.
    fn spawn(&self, name: &'static str, enforce: bool) -> Result<GuardRun, String> {
        let d = self.dir.path();
        let log = d.join(format!("{name}.log"));
        let out = std::fs::File::create(&log).map_err(|e| format!("create {name}.log: {e}"))?;
        let err = out
            .try_clone()
            .map_err(|e| format!("clone {name}.log: {e}"))?;
        let socket = d.join(format!("{name}.sock"));
        let pid_file = d.join(format!("{name}.pid"));
        let mut cmd = Command::new("sudo");
        // sudo resets the environment: the variables go through env(1).
        cmd.arg("env").arg("NO_COLOR=1");
        if enforce {
            cmd.arg(format!(
                "{}=1",
                northnarrow_agent::anti_tamper::bpf_defense::ENFORCE_ENV
            ));
        }
        cmd.arg(&self.agent)
            .arg("--combat-rules")
            .arg(d.join("combat-rules.v4"))
            .arg("--admin-pub")
            .arg(&self.admin_pub)
            .arg("--admin-socket")
            .arg(&socket)
            .arg("--agent-id-file")
            .arg(&self.agent_id_file)
            .arg("--signing-key-file")
            .arg(d.join(format!("{name}.sig.key")))
            .arg("--audit-log-file")
            .arg(d.join(format!("{name}.audit.log")))
            .arg("--shutdown-marker-file")
            .arg(d.join(format!("{name}.shutdown_authorised")))
            .arg("--pid-file")
            .arg(&pid_file)
            .arg("--no-ade")
            .arg("--detect-only")
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err));
        let child = cmd
            .spawn()
            .map_err(|e| format!("spawn the {name} agent: {e}"))?;
        Ok(GuardRun {
            name,
            child,
            socket,
            pid_file,
            log,
        })
    }

    fn signed<'a>(&'a self, socket: &'a Path) -> common::SignedShutdown<'a> {
        common::SignedShutdown {
            nn_admin: &self.nn_admin,
            key: &self.key_a,
            cosign_key: &self.key_b,
            agent_id_file: &self.agent_id_file,
            socket,
        }
    }

    /// A run of the same binary without the variable: the guard re-armed
    /// in observe mode. Stopped signed, else by the fixtures' eviction
    /// (which observe mode allows).
    fn restore_observe(&self) -> Result<(), String> {
        let mut run = self.spawn("restore", false)?;
        let ready = wait_ready(&mut run).and_then(|_| {
            let reg = wait_for_log_line(&run.log, &["own objects registered"], GUARD_LOG_TIMEOUT)
                .ok_or("no BPF self-defence registration line")?;
            if reg.contains("mode=\"observe\"") {
                Ok(())
            } else {
                Err(format!("the guard re-armed in another mode: {reg}"))
            }
        });
        let stopped = common::shutdown_signed(
            &mut run.child,
            &self.signed(&run.socket),
            GUARD_STOP_TIMEOUT,
        )
        .or_else(|e| {
            common::try_quit_agent(&mut run.child, common::QUIT_TIMEOUT)
                .map_err(|q| format!("{e}; then {q}"))
        });
        match (ready, stopped) {
            (Ok(()), Ok(())) => Ok(()),
            (r, s) => Err(format!(
                "{}{}\n{}",
                r.err().unwrap_or_default(),
                s.err().map(|e| format!(" (stop: {e})")).unwrap_or_default(),
                log_tail(&run.log)
            )),
        }
    }
}

#[cfg(feature = "debug-trigger")]
impl Drop for GuardFixture {
    fn drop(&mut self) {
        if let Some(mut run) = self.enforce_run.take() {
            if let Err(e) = common::shutdown_signed(
                &mut run.child,
                &self.signed(&run.socket),
                GUARD_STOP_TIMEOUT,
            ) {
                common::fail_teardown(&format!(
                    "guard e2e: the enforce-mode agent could not be stopped ({e}). It keeps \
                     running and its guard refuses the next fixtures' agents: restart the host.\n{}",
                    log_tail(&run.log)
                ));
                return;
            }
        }
        if let Err(e) = self.restore_observe() {
            common::fail_teardown(&format!(
                "guard e2e: the BPF guard could not be put back in observe mode ({e}). The next \
                 fixtures' agents (other binaries) are refused their registration until the pin \
                 root is purged or the host restarted (nn-lab.sh: lab_purge_pins restarts the guest)."
            ));
        }
    }
}

/// External audit TST-001 (NN-AUD-224) and TST-010 (NN-AUD-231): with the
/// BPF guard in enforce mode root can neither evict the agent from
/// PROTECTED_PIDS nor signal it, the fixtures' teardown recipe fails and
/// says so, and the signed 2-of-N shutdown stops the agent. Fails if the
/// guard does not enforce (the mode line, then the eviction succeeds).
#[cfg(feature = "debug-trigger")]
#[test]
fn bpf_guard_enforce_refuses_protected_pids_write() {
    // As root, or the refusals below would prove nothing.
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run as root (sudo -E cargo test …, docs/integration-test-runbook.md)"
    );
    common::require_bpftool();
    let _eni = EniIptablesGuard::install();
    let mut fx = GuardFixture::new();
    let run = fx.spawn("enforce", true).unwrap_or_else(|e| panic!("{e}"));
    let run = fx.enforce_run.insert(run);
    let pid = wait_ready(run).unwrap_or_else(|e| panic!("{e}"));
    let log = run.log.clone();

    // 1. The mode is read from the agent, not assumed.
    let reg = wait_for_log_line(&log, &["own objects registered"], GUARD_LOG_TIMEOUT)
        .unwrap_or_else(|| panic!("no BPF self-defence registration line\n{}", log_tail(&log)));
    assert!(
        reg.contains("mode=\"enforce\""),
        "the guard did not start in enforce mode: {reg}"
    );

    // 2. The eviction the fixtures' teardown and the old runbook relied on.
    let del = Command::new("sudo")
        .args(["bpftool", "map", "delete", "pinned"])
        .arg(common::protected_pids_pin())
        .arg("key")
        .args(common::pid_key_bytes(pid))
        .output()
        .expect("spawn bpftool");
    let del_err = String::from_utf8_lossy(&del.stderr);
    assert!(
        !del.status.success(),
        "evicting the agent (pid {pid}) from PROTECTED_PIDS succeeded in enforce mode: \
         root can disarm the anti-tamper"
    );
    assert!(
        del_err.contains("Operation not permitted"),
        "bpftool map delete failed, but not with EPERM: {del_err}"
    );

    // 3. Still protected: the kill a root shell tries next is refused.
    let kill = Command::new("kill")
        .args(["-9", &pid.to_string()])
        .output()
        .expect("spawn kill");
    assert!(
        !kill.status.success()
            && String::from_utf8_lossy(&kill.stderr).contains("Operation not permitted"),
        "kill -9 of the agent from root was not refused: {kill:?}"
    );
    let alive = |fx: &mut GuardFixture| {
        let run = fx.enforce_run.as_mut().expect("enforce run");
        matches!(run.child.try_wait(), Ok(None)) && Path::new(&format!("/proc/{pid}")).exists()
    };
    assert!(alive(&mut fx), "the agent is gone after the refused kill");

    // 4. The agent saw both refusals.
    for op in ["op=bpf_map", "op=signal"] {
        assert!(
            wait_for_log_line(&log, &["ANTI-TAMPER DENIAL", op], GUARD_LOG_TIMEOUT).is_some(),
            "no ANTI-TAMPER DENIAL {op} in the agent log\n{}",
            log_tail(&log)
        );
    }

    // 5. TST-010: the fixtures' teardown fails and names the refusal; the
    //    agent is untouched.
    let quit = common::try_quit_agent(
        &mut fx.enforce_run.as_mut().expect("enforce run").child,
        Duration::from_secs(3),
    );
    let msg = quit.expect_err("the fixtures' eviction + SIGQUIT stopped an enforce-mode agent");
    assert!(
        msg.contains("PROTECTED_PIDS") && msg.contains("Operation not permitted"),
        "teardown failure does not name the refusal: {msg}"
    );
    assert!(
        alive(&mut fx),
        "the agent is gone after the refused teardown"
    );

    // 6. The authorised stop: a 2-of-N signed shutdown. Drop then puts
    //    the guard back in observe mode.
    let mut run = fx.enforce_run.take().expect("enforce run");
    if let Err(e) =
        common::shutdown_signed(&mut run.child, &fx.signed(&run.socket), GUARD_STOP_TIMEOUT)
    {
        let tail = log_tail(&run.log);
        fx.enforce_run = Some(run);
        panic!("signed shutdown of the enforce-mode agent failed: {e}\n{tail}");
    }
}
