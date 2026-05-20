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

const SOCKET_POLL_TIMEOUT: Duration = Duration::from_secs(5);
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

/// RAII child-process guard: SIGQUIT on drop so a failed test never
/// leaks a daemon. The agent's Tappa 7 LSM hook blocks SIGKILL and
/// SIGTERM from userland; SIGQUIT is the documented escape hatch
/// (see agent/src/anti_tamper/* docstrings).
struct AgentGuard(Option<Child>);
impl Drop for AgentGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            // SIGQUIT(3) — bypasses the LSM kill block for the agent
            // process. `kill -QUIT $pid` is the supported shutdown.
            unsafe {
                libc::kill(c.id() as i32, libc::SIGQUIT);
            }
            let _ = c.wait();
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

#[test]
fn e2e_force_combat_then_unlock_via_cli() {
    let dir = tempfile::tempdir().expect("tempdir");
    let priv_key = init_admin_keypair(dir.path());
    let (_guard, handles) = spawn_agent(dir.path());
    let nn = handles.nn_admin_path.as_path();
    let socket = handles.socket.as_path();

    // Drive the agent into COMBAT via the debug feature.
    let out = run_nn_admin_at(
        nn,
        &["debug", "force-posture", "combat", "--socket", socket.to_str().unwrap()],
    );
    assert!(
        out.status.success(),
        "debug force-posture failed: stderr={:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Status mirrors the forced state.
    let out =
        run_nn_admin_at(nn, &["status", "--socket", socket.to_str().unwrap(), "--json"]);
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
    let out =
        run_nn_admin_at(nn, &["status", "--socket", socket.to_str().unwrap(), "--json"]);
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

    let (_guard, handles) = spawn_agent(dir.path());
    let nn = handles.nn_admin_path.as_path();
    let socket = handles.socket.as_path();

    // Force Combat to make the test meaningful.
    let out = run_nn_admin_at(
        nn,
        &["debug", "force-posture", "combat", "--socket", socket.to_str().unwrap()],
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

    // Posture still Combat, isolation still engaged.
    let out =
        run_nn_admin_at(nn, &["status", "--socket", socket.to_str().unwrap(), "--json"]);
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
    let (_guard, handles) = spawn_agent(dir.path());
    let nn = handles.nn_admin_path.as_path();
    let socket = handles.socket.as_path();

    // Force Combat.
    let _ = run_nn_admin_at(
        nn,
        &["debug", "force-posture", "combat", "--socket", socket.to_str().unwrap()],
    );

    // Three failures.
    for _ in 0..3 {
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
        assert_eq!(out.status.code(), Some(2));
    }

    // Fourth attempt would be RateLimited if window were short
    // enough; with the 5-minute production window the 4th call
    // still succeeds at the challenge step. Re-enable assertion
    // after the V1.1 override lands.
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
    // V1.1: assert_eq!(out.status.code(), Some(4));
    let _ = out;
}

#[test]
fn e2e_status_no_admin_action_initially() {
    let dir = tempfile::tempdir().expect("tempdir");
    let _priv = init_admin_keypair(dir.path());
    let (_guard, handles) = spawn_agent(dir.path());
    let nn = handles.nn_admin_path.as_path();
    let socket = handles.socket.as_path();

    let out =
        run_nn_admin_at(nn, &["status", "--socket", socket.to_str().unwrap(), "--json"]);
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

    let (_guard, paths) = spawn_agent_b5_with_installs(dir.path(), installed_agent, installed_admin);

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
    assert!(
        marker.contains("entry_hash") && marker.contains("grace_deadline_unix_ts"),
        "marker body unexpected: {marker}"
    );

    // Audit row emitted for the op (B5 wiring).
    let audit_body = std::fs::read_to_string(&paths.audit_log_file)
        .expect("audit log readable post-shutdown");
    let lines: Vec<&str> = audit_body.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        !lines.is_empty(),
        "audit log should have ≥ 1 entry after shutdown"
    );
    let last = lines.last().unwrap();
    assert!(
        last.contains("\"op\":\"shutdown\""),
        "last audit entry should be op=shutdown: {last}"
    );
    assert!(
        last.contains("\"result\":\"success\""),
        "last audit entry should be result=success: {last}"
    );
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

    let (_guard, paths) = spawn_agent_b5_with_installs(dir.path(), installed_agent, installed_admin);

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
    let audit_body =
        std::fs::read_to_string(&paths.audit_log_file).expect("audit log readable");
    assert!(
        audit_body.contains("\"op\":\"rotate_keys_add\""),
        "audit log should have a rotate_keys_add entry: {audit_body}"
    );
    assert!(
        audit_body.contains("\"op\":\"unlock\""),
        "audit log should also have the unlock entry: {audit_body}"
    );
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

    let (_guard, paths) = spawn_agent_b5_with_installs(dir.path(), installed_agent, installed_admin);

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

    // Audit log should now have 3 entries: unlock success +
    // unlock failure + rotate_keys_add success. Verify chain
    // integrity via the CLI.
    let audit_body = std::fs::read_to_string(&paths.audit_log_file)
        .expect("audit log readable");
    let entry_count = audit_body.lines().filter(|l| !l.is_empty()).count();
    assert_eq!(
        entry_count, 3,
        "audit log should have exactly 3 entries: {audit_body}"
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
        body.contains("3 entries") && body.contains("intact"),
        "audit verify output unexpected: {body}"
    );
}
