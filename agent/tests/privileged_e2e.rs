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
use std::time::{Duration, Instant};

mod common;
use common::agent_state::{AgentState, InstalledAgent, Launch};
use common::{install_to_priv_bin, EniIptablesGuard, InstalledBin};

// The agent's start (BTF, the eBPF object, the rules) took ~5 s on a lab
// host running two other guests: the 5-s wait failed a gate run with the
// socket about to open.
const SOCKET_POLL_TIMEOUT: Duration = Duration::from_secs(20);
const SOCKET_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Production combat ruleset used by every scenario. Copied verbatim
/// from `configs/combat-rules.v4` so tests exercise the same bytes
/// the install ships.
fn combat_rules_path() -> PathBuf {
    PathBuf::from(env!("NN_REPO_ROOT"))
        .join("configs")
        .join("combat-rules.v4")
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
    /// The agent's id, which every signed request names (lab PR 256: the
    /// test's own, not the installed agent's `/etc/northnarrow/agent_id`).
    agent_id_file: PathBuf,
    /// Path the tests pass to `run_nn_admin` — the installed
    /// nn-admin under /usr/local/bin/. Holding the corresponding
    /// `InstalledBin` in `_installed_admin` keeps it alive.
    nn_admin_path: PathBuf,
    _installed_agent: InstalledAgent,
    _installed_admin: InstalledBin,
}

/// Spawn the agent from a sudo-installed copy under
/// /usr/local/bin/ so the per-spawn nn-admin invocations don't
/// trip the agent's `R009_RootExecFromUserPath` rule (which
/// kills any root spawn originating from /home/, /tmp/, etc.).
///
/// Lab PR 256: every file the agent writes, its key and its id in
/// `tempdir` ([`AgentState`]). This fixture passed only its socket and its
/// admin keys, so its agent signed the installed agent's audit chain with
/// the installed key (84 `nn-admin-e2etest-*` rows on a lab guest).
fn spawn_agent(tempdir: &Path) -> (AgentGuard, AgentHandles) {
    let (installed_agent, installed_admin) = install_priv_bins();
    let state = AgentState::new(tempdir);
    let rules = tempdir.join("combat-rules.v4");
    std::fs::copy(combat_rules_path(), &rules).expect("copy combat rules");

    // Spawn the installed (root-owned, /usr/local/bin/) agent
    // under sudo so it inherits root privileges + bypasses
    // R009. AgentGuard's SIGQUIT-on-drop still works against
    // the root subprocess because the kill comes from the test
    // process (also root via the outer `sudo cargo test`).
    common::require_bpftool();
    let child = installed_agent
        .command(&state, Launch::Sudo, &[])
        .arg("--combat-rules")
        .arg(&rules)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn northnarrow-agent (installed copy)");
    let guard = AgentGuard(Some(child));

    wait_for_socket(&state.admin_socket());
    let handles = AgentHandles {
        socket: state.admin_socket(),
        agent_id_file: state.agent_id_file(),
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
    let agent_id = handles.agent_id_file.as_path();

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
            "--agent-id-file",
            agent_id.to_str().unwrap(),
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
            "--agent-id-file",
            agent_id.to_str().unwrap(),
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
    let agent_id = handles.agent_id_file.as_path();

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
            "--agent-id-file",
            agent_id.to_str().unwrap(),
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
            "--agent-id-file",
            agent_id.to_str().unwrap(),
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
    let agent_id = handles.agent_id_file.as_path();

    for attempt in 1..=4 {
        let out = run_nn_admin_at(
            nn,
            &[
                "unlock",
                "--key",
                other_priv.to_str().unwrap(),
                "--agent-id-file",
                agent_id.to_str().unwrap(),
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
            "--agent-id-file",
            agent_id.to_str().unwrap(),
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
// All three use the agent-spawn helper `spawn_agent_b5`, which
// returns the per-test paths they inspect. Lab PR 256: every agent of
// this file keeps all of its state in its tempdir (`AgentState`); this
// helper's three B5-era files and id were not enough, its agent appended
// rows under its own key to the installed agent's detection chain.
//
// R009 (root-exec-from-/home/) is not tripped because none of
// these tests trigger malicious-looking activity — they only
// drive admin operations through the documented CLI surface.

const NN_ADMIN_OP_TIMEOUT: Duration = Duration::from_secs(10);

/// PHASE_D_003 agent-spawn helper: like `spawn_agent`, and returns
/// the running child + every per-test path the caller might need
/// to inspect (all in the tempdir, [`AgentState`]).
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
    _installed_agent: InstalledAgent,
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
fn install_priv_bins() -> (InstalledAgent, InstalledBin) {
    let installed_agent = InstalledAgent::install();
    let installed_admin = install_to_priv_bin(Path::new(nn_admin_bin()));
    (installed_agent, installed_admin)
}

/// Two-step pattern step 2: spawn the agent using the already-
/// installed binaries.
fn spawn_agent_b5_with_installs(
    tempdir: &Path,
    installed_agent: InstalledAgent,
    installed_admin: InstalledBin,
) -> (AgentGuard, B5Paths) {
    let state = AgentState::new(tempdir);
    let paths = B5Paths {
        socket: state.admin_socket(),
        admin_pub: state.admin_pub(),
        agent_id_file: state.agent_id_file(),
        signing_key_file: state.signing_key(),
        audit_log_file: state.audit_log(),
        shutdown_marker_file: state.shutdown_marker(),
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
    let child = paths
        ._installed_agent
        .command(&state, Launch::Sudo, &[])
        .arg("--combat-rules")
        .arg(&rules)
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
/// #482's CI (ubuntu2404): the audit row after `op=shutdown` was the
/// run's `telemetry_loss at:start` — the shutdown was answered before the
/// start beat. The boot binds the admin socket only once the agent is
/// armed and its start beat is written (`boot::admin`), and this test now
/// waits for the agent to end (it stops itself on the signed shutdown,
/// exit 0) and asserts the exact tail the stop writes after the op, in its
/// order: the event bus's close (its unsigned drops, `event_bus_stop` when
/// it still held events), the stop beat (the capability manifest's pending
/// changes, its `telemetry_loss` at: stop), `agent_stop` (`reason:
/// admin_shutdown`) last — never a start row, and no other row.
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

    let (mut guard, paths) =
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
    let parsed = ::nn_proto::shutdown_marker::ShutdownMarker::parse(&marker)
        .unwrap_or_else(|e| panic!("marker body unexpected ({e}): {marker}"));
    let keys = ::nn_proto::admin_quorum::parse_admin_pub(
        &std::fs::read_to_string(&paths.admin_pub).expect("admin.pub"),
    )
    .expect("admin.pub parses");
    let agent_id = ::nn_proto::shutdown_marker::parse_agent_id(
        &std::fs::read_to_string(&paths.agent_id_file).expect("agent_id"),
    )
    .expect("agent_id parses");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let exp = ::nn_proto::shutdown_marker::Expectation {
        keys: &keys,
        agent_id,
        agent_pid: parsed.agent_pid,
        agent_started: None,
        now,
    };
    ::nn_proto::shutdown_marker::verify(&parsed, &exp, |_| false)
        .unwrap_or_else(|e| panic!("the watchdog would refuse the agent's marker: {e}"));

    // The agent stops itself on the signed shutdown (the event loop ends,
    // the stop runs, exit 0): its audit chain is complete once it has
    // exited — the tail is read whole, never mid-stop.
    let child = guard.0.as_mut().expect("the agent's child");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(st) = child.try_wait().expect("wait for the agent") {
            break st;
        }
        assert!(
            Instant::now() < deadline,
            "the agent did not stop within 30 s of its signed shutdown"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        status.success(),
        "the agent's exit after the shutdown: {status:?}"
    );
    guard.0 = None;

    // Audit row emitted for the op (B5 wiring), then the stop's own rows.
    let audit_body =
        std::fs::read_to_string(&paths.audit_log_file).expect("audit log readable post-shutdown");
    let rows: Vec<serde_json::Value> = audit_body
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).expect("audit line is JSON"))
        .collect();
    let op = |r: &serde_json::Value| r["op"].as_str().unwrap_or_default().to_string();
    let shutdowns: Vec<usize> = (0..rows.len())
        .filter(|i| op(&rows[*i]) == "shutdown")
        .collect();
    assert_eq!(shutdowns.len(), 1, "one op=shutdown: {audit_body}");
    let at = shutdowns[0];
    assert_eq!(
        rows[at]["result"], "success",
        "op=shutdown entry should be result=success: {}",
        rows[at]
    );
    // the run's start rows all precede the op (the socket was bound after
    // them): the boot's `agent_boot` and `capability_manifest`, the start
    // beat's `telemetry_loss`
    let start_loss = rows
        .iter()
        .position(|r| op(r) == "telemetry_loss" && r["extra"]["at"] == "start")
        .unwrap_or_else(|| panic!("no start beat's telemetry_loss: {audit_body}"));
    for start in ["agent_boot", "capability_manifest"] {
        let i = rows
            .iter()
            .position(|r| op(r) == start)
            .unwrap_or_else(|| panic!("no {start}: {audit_body}"));
        assert!(i < at, "{start} after the shutdown: {audit_body}");
    }
    assert!(
        start_loss < at,
        "the start beat after the shutdown: {audit_body}"
    );
    // the exact tail: the stop's rows, in the order the stop writes them —
    // 1. the event bus's close (`sensor.stop_bus()`): its drops not signed
    //    yet (`event_bus_drop`, `event_bus_coalesced`, `event_bus_capped`),
    //    then `event_bus_stop` when it still held events (round i24's run 4:
    //    ten events queued at the close);
    // 2. the stop beat (`heartbeat.stop`): the capability manifest's pending
    //    changes (`capability_manifest_change`, flushed), then its
    //    `telemetry_loss` (at: stop), exactly one;
    // 3. `agent_stop` (reason admin_shutdown), last.
    let tail = &rows[at + 1..];
    let shown = || {
        tail.iter()
            .map(|r| format!("{} {}", op(r), r["extra"]))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let mut i = 0;
    let mut skip = |ops: &[&str], at_most: usize| {
        let mut n = 0;
        while i < tail.len() && n < at_most && ops.contains(&op(&tail[i]).as_str()) {
            i += 1;
            n += 1;
        }
    };
    skip(
        &["event_bus_drop", "event_bus_coalesced", "event_bus_capped"],
        usize::MAX,
    );
    skip(&["event_bus_stop"], 1);
    skip(&["capability_manifest_change"], usize::MAX);
    let rest = &tail[i..];
    assert_eq!(
        rest.len(),
        2,
        "the stop's rows after op=shutdown (no other row):\n{}",
        shown()
    );
    assert!(
        op(&rest[0]) == "telemetry_loss" && rest[0]["extra"]["at"] == "stop",
        "the stop beat's telemetry_loss (at: stop) after the bus's close and the manifest's \
         changes:\n{}",
        shown()
    );
    assert!(
        op(&rest[1]) == "agent_stop" && rest[1]["extra"]["reason"] == "admin_shutdown",
        "agent_stop (reason admin_shutdown) last:\n{}",
        shown()
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
            // Lab PR 217: the signed unlock is bound to this install.
            "--agent-id-file",
            paths.agent_id_file.to_str().unwrap(),
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
            // Lab PR 217: the signed unlock is bound to this install.
            "--agent-id-file",
            paths.agent_id_file.to_str().unwrap(),
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
            // Lab PR 217: the signed unlock is bound to this install.
            "--agent-id-file",
            paths.agent_id_file.to_str().unwrap(),
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
    // guest, the installed agent's FIM baseline, signed by another key),
    // the start of head anchoring and the background chain check (lab PR
    // 160: `chain_numbering_started`, `chain_verify`).
    // Verify chain integrity via the CLI.
    let audit_body = std::fs::read_to_string(&paths.audit_log_file).expect("audit log readable");
    let entries: Vec<serde_json::Value> = audit_body
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).expect("audit line is JSON"))
        .collect();
    let ops: Vec<(String, String)> = entries
        .iter()
        .filter(|e| {
            // R12c-2 (lab PR 270): the heartbeat's `telemetry_loss` rows
            // come with its beats, on their own clock, as the background
            // chain check's do (the heartbeat's tests read them). R13 (lab
            // PR 271): so do the capability manifest's changes — the
            // telemetry probe's first round, 20 s after the start, is one
            // (the manifest's tests read them); the boot's own row stays
            // in the list below.
            ![
                "integrity_drift",
                "chain_numbering_started",
                "chain_verify",
                "telemetry_loss",
                "capability_manifest_change",
            ]
            .contains(&e["op"].as_str().unwrap_or_default())
        })
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
            // Lab PR 185 (MAIN-009, EVD-020): a fresh state dir mints the
            // agent's id at boot, signed before `agent_boot`.
            ("agent_id_minted", "success"),
            ("agent_boot", "success"),
            // Lab PR 218: every boot signs its capability manifest.
            ("capability_manifest", "success"),
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
    agent_id_file: PathBuf,
    key_a: PathBuf,
    key_b: PathBuf,
    enforce_run: Option<GuardRun>,
    // Removed only after `drop` ran: the restore run needs this binary.
    agent: InstalledAgent,
    _installed_admin: InstalledBin,
}

#[cfg(feature = "debug-trigger")]
impl GuardFixture {
    /// Installed agent + nn-admin, two keys with the `shutdown` role. The
    /// runs are agents of one directory (`AgentState::named`): one id and
    /// these keys, each its own signing key, chains and socket.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let (installed_agent, installed_admin) = install_priv_bins();
        let nn_admin = installed_admin.path.clone();
        let shared = AgentState::new(dir.path());
        let admin_pub = shared.admin_pub();
        std::fs::write(&admin_pub, "").expect("touch admin.pub");
        // lot 290: and the trusted-installer role, for the window in which
        // the test reads the agent's link ids (a read handle on its maps is
        // refused outside one in enforce mode)
        let (key_a, _) = init_admin_keypair_with_roles(
            &nn_admin,
            dir.path(),
            &admin_pub,
            "admin_a",
            "unlock,shutdown,trusted-installer",
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
            agent_id_file: shared.agent_id_file(),
            dir,
            nn_admin,
            key_a,
            key_b,
            enforce_run: None,
            agent: installed_agent,
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
        let state = AgentState::named(d, name);
        // Lab PR 265 (review #466 F4-bis): an agent whose key is absent
        // where the install's id is on record refuses its start (the key was
        // removed or hidden) — and the runs of one directory share the id.
        // Each run's key is made first, as a first install's start would.
        northnarrow_agent::audit::AgentSigningKey::load_or_bootstrap(&state.signing_key())
            .map_err(|e| format!("the {name} agent's key: {e:#}"))?;
        let mut env = vec![("NO_COLOR", "1")];
        if enforce {
            env.push((
                northnarrow_agent::anti_tamper::bpf_defense::ENFORCE_ENV,
                "1",
            ));
        }
        let child = self
            .agent
            .command(&state, Launch::Sudo, &env)
            .arg("--combat-rules")
            .arg(d.join("combat-rules.v4"))
            .arg("--detect-only")
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .map_err(|e| format!("spawn the {name} agent: {e}"))?;
        Ok(GuardRun {
            name,
            child,
            socket: state.admin_socket(),
            pid_file: state.pid_file(),
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

    /// Lot 290: a trusted-installer window of `secs` on run `name`'s agent,
    /// opened the way `install.sh` opens one.
    fn grant_window(&self, name: &'static str, secs: u32) -> Result<(), String> {
        let state = AgentState::named(self.dir.path(), name);
        let out = Command::new(&self.nn_admin)
            .arg("trusted-installer-grant")
            .arg("--key")
            .arg(&self.key_a)
            .arg("--window-secs")
            .arg(secs.to_string())
            .args(state.client_args())
            .output()
            .map_err(|e| format!("spawn nn-admin trusted-installer-grant: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "trusted-installer-grant failed: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ))
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
/// Lab PR 215: nor take a handle by id on one of its links, while the
/// enumeration of the link ids stays allowed.
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

    // 3b. Lab PR 215: a handle by id on one of the agent's links is refused
    //     (the hook had BPF_LINK_GET_FD_BY_ID at 31, BPF_LINK_GET_NEXT_ID:
    //     the handle was granted and not recorded), and the enumeration
    //     from each of its link ids — the step `bpftool link list` takes —
    //     is not (it was refused, and recorded as a denial). The ids come
    //     from OWN_BPF_IDS through read-only map handles — lot 290: inside a
    //     trusted-installer window (outside one a read handle on the
    //     agent's maps is refused too), the checks after it has closed.
    const WINDOW_SECS: u32 = 5;
    fx.grant_window("enforce", WINDOW_SECS)
        .unwrap_or_else(|e| panic!("{e}\n{}", log_tail(&log)));
    let links = common::raw_bpf::own_link_ids()
        .unwrap_or_else(|e| panic!("the agent's link ids: {e}\n{}", log_tail(&log)));
    std::thread::sleep(Duration::from_secs(u64::from(WINDOW_SECS) + 2));
    assert_eq!(
        common::raw_bpf::link_fd_by_id(links[0]),
        Err(libc::EPERM),
        "BPF_LINK_GET_FD_BY_ID on the agent's link {} from root was not refused in enforce \
         mode (Ok = granted)",
        links[0]
    );
    for id in &links {
        if let Err(e) = common::raw_bpf::link_next_id(*id) {
            panic!("BPF_LINK_GET_NEXT_ID from the agent's link {id} failed with errno {e}: the enumeration gives no handle and must not be refused");
        }
    }

    // 4. The agent saw the three refusals (lot 290: the eviction's handle
    //    on the pinned PROTECTED_PIDS is refused at its path now —
    //    `bpf_handle` — before any write handle exists).
    for op in ["op=bpf_handle", "op=signal", "op=bpf_link"] {
        assert!(
            wait_for_log_line(&log, &["ANTI-TAMPER DENIAL", op], GUARD_LOG_TIMEOUT).is_some(),
            "no ANTI-TAMPER DENIAL {op} in the agent log\n{}",
            log_tail(&log)
        );
    }

    // 4b. Lot 290: outside the window the same read-only handles are refused.
    //     After the log's checks: it opens every map of the host, and each of
    //     the agent's is a refusal (a burst the denial budget holds, which
    //     would hide the bpf_link line above — CI's second run).
    assert!(
        common::raw_bpf::own_link_ids().is_err(),
        "OWN_BPF_IDS read through a read-only handle outside a window in enforce mode (lot 290: \
         refused)"
    );
    // Lot 293 (external bug hunt BUG13, closed by lot 290): and a read-only
    // handle through the pin — the one a foreign program would be loaded
    // against to rewrite PROTECTED_PIDS — is refused with EPERM (its record
    // is the `bpf_handle` of step 4; the burst above may hold this one's in
    // NN-L-AT-001's budget).
    assert_eq!(
        common::raw_bpf::pinned_rdonly(&common::protected_pids_pin()),
        Err(libc::EPERM),
        "a read-only handle on the pinned PROTECTED_PIDS from root was not refused in enforce \
         mode (Ok = granted)"
    );

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

// ── Lot 293 — external bug hunt BUG14: a signal through a file's owner ─

/// The ways a root process arms a file's owner on a protected process: the
/// owner set by `F_SETOWN`, `F_SETOWN_EX` (a thread) or `FIOSETOWN` (a
/// socket), the signal by `F_SETSIG` (0 = the plain SIGIO), the mode by
/// `O_ASYNC` or `FIOASYNC`; then one byte written makes the kernel deliver
/// it — through `file_send_sigiotask`, never `task_kill`.
#[cfg(feature = "debug-trigger")]
mod owner_signal {
    use std::io;

    /// `<asm-generic/ioctls.h>` / `<linux/sockios.h>`, and
    /// `<asm-generic/fcntl.h>`'s (the libc crate lacks some of them).
    const FIOASYNC: libc::c_ulong = 0x5452;
    const FIOSETOWN: libc::c_ulong = 0x8901;
    const F_SETSIG: libc::c_int = 10;
    const F_SETOWN_EX: libc::c_int = 15;
    const F_OWNER_TID: libc::c_int = 0;

    /// `struct f_owner_ex`.
    #[repr(C)]
    struct OwnerEx {
        kind: libc::c_int,
        pid: libc::pid_t,
    }

    #[derive(Clone, Copy, Debug)]
    pub enum Owner {
        /// `F_SETOWN` on a pipe's read end.
        Pid,
        /// `F_SETOWN_EX` with `F_OWNER_TID` (the target's main thread).
        Tid,
        /// `FIOSETOWN` + `FIOASYNC` on a socket.
        Socket,
    }

    fn check(r: libc::c_int, what: &str) -> io::Result<()> {
        if r < 0 {
            Err(io::Error::new(
                io::Error::last_os_error().kind(),
                format!("{what}: {}", io::Error::last_os_error()),
            ))
        } else {
            Ok(())
        }
    }

    /// Arm a fresh descriptor's owner on `target` with `sig` (0: SIGIO),
    /// make it ready (one byte), close everything.
    pub fn fire(owner: Owner, target: u32, sig: libc::c_int) -> io::Result<()> {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: plain syscalls on descriptors this function owns; the
        // pointers passed point at live locals.
        unsafe {
            match owner {
                Owner::Socket => check(
                    libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()),
                    "socketpair",
                )?,
                _ => check(libc::pipe(fds.as_mut_ptr()), "pipe")?,
            }
            let (armed, other) = (fds[0], fds[1]);
            let res = (|| {
                match owner {
                    Owner::Pid => check(
                        libc::fcntl(armed, libc::F_SETOWN, target as libc::c_int),
                        "F_SETOWN",
                    )?,
                    Owner::Tid => {
                        let ex = OwnerEx {
                            kind: F_OWNER_TID,
                            pid: target as libc::pid_t,
                        };
                        check(
                            libc::fcntl(armed, F_SETOWN_EX, &ex as *const OwnerEx),
                            "F_SETOWN_EX",
                        )?
                    }
                    Owner::Socket => {
                        let pid = target as libc::c_int;
                        check(libc::ioctl(armed, FIOSETOWN, &pid), "FIOSETOWN")?
                    }
                }
                if sig != 0 {
                    check(libc::fcntl(armed, F_SETSIG, sig), "F_SETSIG")?;
                }
                match owner {
                    Owner::Socket => {
                        let on: libc::c_int = 1;
                        check(libc::ioctl(armed, FIOASYNC, &on), "FIOASYNC")?
                    }
                    _ => {
                        let fl = libc::fcntl(armed, libc::F_GETFL);
                        check(fl, "F_GETFL")?;
                        check(
                            libc::fcntl(armed, libc::F_SETFL, fl | libc::O_ASYNC),
                            "F_SETFL O_ASYNC",
                        )?
                    }
                }
                let n = libc::write(other, b"x".as_ptr().cast(), 1);
                if n != 1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            })();
            libc::close(armed);
            libc::close(other);
            res
        }
    }

    /// `pidfd_send_signal(pidfd_open(target), sig)`: the errno, or `Ok`.
    pub fn pidfd_signal(target: u32, sig: libc::c_int) -> Result<(), i32> {
        // SAFETY: raw syscalls; the descriptor is ours and closed.
        unsafe {
            let fd = libc::syscall(libc::SYS_pidfd_open, target as libc::pid_t, 0u32);
            if fd < 0 {
                return Err(io::Error::last_os_error().raw_os_error().unwrap_or(0));
            }
            let r = libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd as libc::c_int,
                sig,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            );
            let e = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            libc::close(fd as libc::c_int);
            if r < 0 {
                Err(e)
            } else {
                Ok(())
            }
        }
    }
}

/// The agent log's denial lines of the SIGIO path for signal `sig`.
#[cfg(feature = "debug-trigger")]
fn sigio_denials(log: &Path, pid: u32, sig: i32) -> usize {
    let target = format!("target_ino={pid}");
    let signal = format!("target_dev={sig}");
    read_agent_log(log)
        .lines()
        .filter(|l| {
            l.contains("ANTI-TAMPER DENIAL")
                && l.contains("op=sigio")
                && l.contains(&target)
                && l.split_whitespace().any(|w| w == signal)
        })
        .count()
}

/// External bug hunt BUG14 (P0): root killed the agent and the watchdog
/// through a file's owner — `F_SETOWN` + `F_SETSIG` + `O_ASYNC` on a pipe
/// and one write; the kernel delivers that signal through
/// `file_send_sigiotask`, never `task_kill`, so nothing refused it and
/// nothing recorded it. Now: the plain SIGIO, an `F_SETSIG` SIGKILL, the
/// `F_SETOWN_EX` thread owner and a socket's `FIOSETOWN` are refused — the
/// agent lives and each refusal is signed (`op=sigio`) — and a pidfd's
/// SIGKILL is refused by `task_kill` (EPERM). Inside a signed
/// trusted-installer window the window's signal grant applies: a stop
/// signal of its mask (SIGCONT, harmless) passes and is not recorded, the
/// plain SIGIO is still refused.
#[cfg(feature = "debug-trigger")]
#[test]
fn signals_through_a_file_s_owner_are_refused_and_signed() {
    use owner_signal::{fire, pidfd_signal, Owner};
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run as root (sudo -E cargo test …, docs/integration-test-runbook.md)"
    );
    let _eni = EniIptablesGuard::install();
    let mut fx = GuardFixture::new();
    let run = fx.spawn("sigio", false).unwrap_or_else(|e| panic!("{e}"));
    let run = fx.enforce_run.insert(run);
    let pid = wait_ready(run).unwrap_or_else(|e| panic!("{e}"));
    let log = run.log.clone();
    let alive = |fx: &mut GuardFixture| {
        let run = fx.enforce_run.as_mut().expect("the sigio run");
        matches!(run.child.try_wait(), Ok(None)) && Path::new(&format!("/proc/{pid}")).exists()
    };

    // 1. Outside a window. One second apart: the kernel signs one refusal
    //    per caller and operation a second.
    for (owner, sig, name) in [
        (Owner::Pid, 0, "F_SETOWN + O_ASYNC, the plain SIGIO"),
        (
            Owner::Pid,
            libc::SIGKILL,
            "F_SETOWN + F_SETSIG(SIGKILL) + O_ASYNC",
        ),
        (
            Owner::Tid,
            libc::SIGKILL,
            "F_SETOWN_EX(F_OWNER_TID) + F_SETSIG(SIGKILL)",
        ),
        (
            Owner::Socket,
            libc::SIGKILL,
            "FIOSETOWN + F_SETSIG(SIGKILL) + FIOASYNC",
        ),
    ] {
        let delivered = if sig == 0 { libc::SIGIO } else { sig };
        let before = sigio_denials(&log, pid, delivered);
        fire(owner, pid, sig).unwrap_or_else(|e| panic!("{name}: arming failed: {e}"));
        std::thread::sleep(Duration::from_millis(1200));
        assert!(
            alive(&mut fx),
            "{name}: the agent (pid {pid}) died — the signal through its file's owner was \
             delivered\n{}",
            log_tail(&log)
        );
        let deadline = Instant::now() + GUARD_LOG_TIMEOUT;
        while sigio_denials(&log, pid, delivered) <= before {
            assert!(
                Instant::now() < deadline,
                "{name}: no signed refusal (op=sigio target_dev={delivered})\n{}",
                log_tail(&log)
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    // a pidfd's signal goes through task_kill: refused there
    assert_eq!(
        pidfd_signal(pid, libc::SIGKILL),
        Err(libc::EPERM),
        "pidfd_send_signal(SIGKILL) to the agent from root was not refused"
    );
    assert!(
        alive(&mut fx),
        "the agent is gone after the pidfd's SIGKILL"
    );

    // 2. Inside a window: the grant's stop signals pass (SIGCONT is one of
    //    them, and harmless), the plain SIGIO does not.
    const WINDOW_SECS: u32 = 8;
    fx.grant_window("sigio", WINDOW_SECS)
        .unwrap_or_else(|e| panic!("{e}\n{}", log_tail(&log)));
    std::thread::sleep(Duration::from_millis(1200));
    let cont_before = sigio_denials(&log, pid, libc::SIGCONT);
    let io_before = sigio_denials(&log, pid, libc::SIGIO);
    fire(Owner::Pid, pid, libc::SIGCONT).expect("SIGCONT armed inside the window");
    std::thread::sleep(Duration::from_millis(1200));
    fire(Owner::Pid, pid, 0).expect("SIGIO armed inside the window");
    let deadline = Instant::now() + GUARD_LOG_TIMEOUT;
    while sigio_denials(&log, pid, libc::SIGIO) <= io_before {
        assert!(
            Instant::now() < deadline,
            "inside the window the plain SIGIO was not refused and signed\n{}",
            log_tail(&log)
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(alive(&mut fx), "the agent is gone after the window's SIGIO");
    assert_eq!(
        sigio_denials(&log, pid, libc::SIGCONT),
        cont_before,
        "inside the window the grant's SIGCONT was refused"
    );
    // the window's end
    std::thread::sleep(Duration::from_secs(u64::from(WINDOW_SECS) + 1));
    fire(Owner::Pid, pid, libc::SIGCONT).expect("SIGCONT armed after the window");
    let deadline = Instant::now() + GUARD_LOG_TIMEOUT;
    while sigio_denials(&log, pid, libc::SIGCONT) <= cont_before {
        assert!(
            Instant::now() < deadline,
            "after the window SIGCONT through the file's owner was not refused\n{}",
            log_tail(&log)
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // 3. The authorised stop. Drop then restores the guard's mode.
    let mut run = fx.enforce_run.take().expect("the sigio run");
    if let Err(e) =
        common::shutdown_signed(&mut run.child, &fx.signed(&run.socket), GUARD_STOP_TIMEOUT)
    {
        let tail = log_tail(&run.log);
        fx.enforce_run = Some(run);
        panic!("signed shutdown of the agent failed: {e}\n{tail}");
    }
}

// ── Lab PR 179 — external audit ASK-012 (NN-AUD-238) ────────────────

/// External audit ASK-012 (NN-AUD-238): the admin socket's only gate was
/// its mode 0600; a peer of another uid was served when the mode or the
/// directory had been widened. The serve loop now checks `SO_PEERCRED`:
/// uid 65534, on a socket chmod-ed 0666 in a 0711 directory, connects
/// and is closed without a reply, one signed `integrity_drift`
/// (`admin_socket_foreign_peer`) names it, and root is still answered.
/// In process (no agent binary): the serve loop is the agent's; the
/// foreign peer is a thread whose credentials alone drop to 65534 (raw
/// `setres[ug]id`, which change the calling thread only).
#[test]
fn admin_socket_refuses_a_peer_of_another_uid() {
    use northnarrow_agent::admin_cli::run_status;
    use northnarrow_agent::admin_socket::{serve_with_audit_log, FOREIGN_PEER_KIND};
    use northnarrow_agent::anti_tamper::admin_auth::AdminAuth;
    use northnarrow_agent::anti_tamper::network_isolate::NetworkIsolator;
    use northnarrow_agent::audit::{AgentSigningKey, AuditLog};
    use northnarrow_agent::posture::PostureMachine;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    // SAFETY: geteuid has no preconditions.
    assert_eq!(unsafe { libc::geteuid() }, 0, "this test needs root");
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("admin.sock");
    let log_path = dir.path().join("audit.log");
    let pub_path = dir.path().join("admin.pub");
    let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    std::fs::write(
        &pub_path,
        format!("{}\n", hex::encode(key.verifying_key().to_bytes())),
    )
    .unwrap();
    let auth = Arc::new(AdminAuth::load(&pub_path).unwrap());
    let isolator = Arc::new(NetworkIsolator::new(combat_rules_path()).unwrap());
    let posture = Arc::new(PostureMachine::new());
    let sig = AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.sig.key")).unwrap();
    let audit = Arc::new(parking_lot::Mutex::new(
        AuditLog::open(&log_path, sig, [0u8; 16]).unwrap(),
    ));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.spawn(serve_with_audit_log(
        socket.clone(),
        auth,
        posture,
        isolator,
        dir.path().join("marker"),
        None,
        Arc::clone(&audit),
    ));
    wait_for_socket(&socket);
    run_status(&socket).expect("root is answered");

    // The widened modes a mistaken chmod leaves: anyone may connect.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o711)).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666)).unwrap();
    let s = socket.clone();
    let foreign = std::thread::spawn(move || {
        // SAFETY: raw syscalls on this thread's own credentials.
        unsafe {
            assert_eq!(
                libc::syscall(libc::SYS_setgroups, 0usize, std::ptr::null::<libc::gid_t>()),
                0
            );
            assert_eq!(libc::syscall(libc::SYS_setresgid, 65534, 65534, 65534), 0);
            assert_eq!(libc::syscall(libc::SYS_setresuid, 65534, 65534, 65534), 0);
        }
        run_status(&s).map(|_| ()).map_err(|e| format!("{e:#}"))
    })
    .join()
    .unwrap();
    let err = foreign.expect_err("uid 65534 must not be answered");
    assert!(
        !err.contains("connecting to"),
        "the peer must have connected (mode 0666) and been closed: {err}"
    );
    run_status(&socket).expect("root is still answered");

    let rows: Vec<serde_json::Value> = std::fs::read_to_string(&log_path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .filter(|v: &serde_json::Value| {
            v["op"] == "integrity_drift" && v["extra"]["kind"] == FOREIGN_PEER_KIND
        })
        .collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    let detail = rows[0]["extra"]["detail"].as_str().unwrap();
    assert!(
        detail.contains("a connection from uid 65534 gid 65534"),
        "{detail}"
    );
    drop(rt);
}

// ── External audit NN-AUD-423 (TST-017): the agent without its admin key ──

/// AUT-004 made an agent started without `admin.pub` say so: it cannot be
/// unlocked, shut down or upgraded through its socket, so it logs an ERROR
/// and writes a signed `subsystem_degraded` record, and runs on. No test
/// held it — `privileged_map_pin` booted that way for months without
/// looking. The agent here has every path in the tempdir and no
/// `admin.pub`: the ERROR line is in its log, no admin socket appears, the
/// audit chain holds the record (`detail` starting "admin socket
/// disabled", `at_boot`) and verifies, and the agent is still running.
#[test]
fn agent_without_admin_pub_starts_degraded_and_says_so() {
    // Declared first: removed after the agent stopped and the chain was read.
    let (installed_agent, installed_admin) = install_priv_bins();
    let dir = tempfile::tempdir().expect("tempdir");
    let d = dir.path();
    let rules = d.join("combat-rules.v4");
    std::fs::copy(combat_rules_path(), &rules).expect("copy combat rules");
    // Lab PR 256: every file in the tempdir; `admin.pub` is never created.
    let state = AgentState::new(d);
    let socket = state.admin_socket();
    let audit_log = state.audit_log();
    let signing_key = state.signing_key();
    let log_path = d.join("agent.log");
    let log = std::fs::File::create(&log_path).expect("create agent.log");
    let log_err = log.try_clone().expect("clone the log handle");

    common::require_bpftool();
    let child = installed_agent
        .command(&state, Launch::Sudo, &[("NO_COLOR", "1")])
        .arg("--combat-rules")
        .arg(&rules)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .expect("spawn northnarrow-agent without admin.pub");
    let mut guard = AgentGuard(Some(child));
    let agent_log = || common::strip_ansi(&std::fs::read_to_string(&log_path).unwrap_or_default());

    let record = common::wait_until(Duration::from_secs(60), || {
        common::read_jsonl_strict(&audit_log).into_iter().find(|r| {
            r["op"] == "integrity_drift"
                && r["extra"]["kind"] == "subsystem_degraded"
                && r["extra"]["detail"]
                    .as_str()
                    .is_some_and(|s| s.starts_with("admin socket disabled"))
        })
    })
    .unwrap_or_else(|| {
        panic!(
            "no signed subsystem_degraded \"admin socket disabled\" in {} within 60s; rows: \
             {:?}\n--- agent log ---\n{}",
            audit_log.display(),
            common::read_jsonl_strict(&audit_log),
            agent_log()
        )
    });
    assert_eq!(record["extra"]["at_boot"], true, "{record}");
    assert_eq!(record["key_fp"], "agent-self", "{record}");

    let child = guard.0.as_mut().expect("agent child");
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "the agent must run on, degraded\n{}",
        agent_log()
    );
    assert!(
        !socket.exists(),
        "an agent without admin.pub must not open its admin socket ({})",
        socket.display()
    );
    let text = agent_log();
    assert!(
        text.lines().any(|l| l.contains("ERROR")
            && l.contains("admin pub key file missing or invalid; admin socket disabled")),
        "no ERROR line for the missing admin.pub in the agent log:\n{text}"
    );

    // The record is in the signed chain: stop the agent, then verify it.
    drop(guard);
    let out = Command::new(&installed_admin.path)
        .args(["audit", "verify", "--from"])
        .arg(&audit_log)
        .arg("--agent-sig-key")
        .arg(&signing_key)
        .output()
        .expect("spawn nn-admin audit verify");
    assert!(
        out.status.success(),
        "audit verify refused the chain: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Lot 300: the sensor self-test's first round finds the module-load
/// programs linked — `module_load`'s word is `seen`, never `missed`. Since
/// lot 285 the module files' write history (`module_write_observe`, on
/// `file_open`) was pinned in a directory of its own beside the pin root
/// and its link dropped once pinned; the round's attach check, which reads
/// the links the agent holds and the pin root's `link_*` pins, found it
/// detached in every round on every host — a signed degradation at the
/// first round, an alert at the second (lot 293's lab: 5.15 and 6.12).
#[test]
fn the_sensor_self_test_finds_the_module_load_programs_linked() {
    // Declared first: removed after the agent stopped.
    let (installed_agent, _installed_admin) = install_priv_bins();
    let dir = tempfile::tempdir().expect("tempdir");
    let d = dir.path();
    let rules = d.join("combat-rules.v4");
    std::fs::copy(combat_rules_path(), &rules).expect("copy combat rules");
    let state = AgentState::new(d);
    let audit_log = state.audit_log();
    let log_path = d.join("agent.log");
    let log = std::fs::File::create(&log_path).expect("create agent.log");
    let log_err = log.try_clone().expect("clone the log handle");

    common::require_bpftool();
    let _eni = EniIptablesGuard::install();
    let child = installed_agent
        .command(&state, Launch::Sudo, &[("NO_COLOR", "1")])
        .arg("--combat-rules")
        .arg(&rules)
        .arg("--detect-only")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .expect("spawn northnarrow-agent");
    let _guard = AgentGuard(Some(child));
    let agent_log = || common::strip_ansi(&std::fs::read_to_string(&log_path).unwrap_or_default());
    let tail = |text: String| {
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    };

    // The first round runs 20 s after the start (`FIRST_ROUND_SECS`), its
    // events within 5 s; every source's first word goes into the manifest
    // at once (the journal's line, the signed row within a minute).
    let words = common::wait_until(Duration::from_secs(90), || {
        agent_log()
            .lines()
            .find(|l| {
                l.contains("the capability manifest changed")
                    && l.contains("source module_load: sensor self-test pending →")
            })
            .map(str::to_string)
    })
    .unwrap_or_else(|| {
        panic!(
            "no sensor self-test round with a word on module_load within 90 s\n{}",
            tail(agent_log())
        )
    });
    assert!(
        words.contains("source module_load: sensor self-test pending → seen"),
        "module_load's first self-test word is not `seen` (its programs not all linked where \
         the attach check reads them): {words}"
    );
    let text = agent_log();
    assert!(
        !text
            .lines()
            .any(|l| l.contains("SENSOR SELF-TEST") && l.contains("sensor=\"module_load\"")),
        "a module_load self-test miss in the agent log\n{}",
        tail(text.clone())
    );
    let missed: Vec<serde_json::Value> = common::read_jsonl_strict(&audit_log)
        .into_iter()
        .filter(|r| {
            r["op"] == "integrity_drift"
                && r["extra"]["kind"] == "subsystem_degraded"
                && r["extra"]["detail"]
                    .as_str()
                    .is_some_and(|s| s.contains("self-test") && s.contains("module_load"))
        })
        .collect();
    assert!(
        missed.is_empty(),
        "a signed self-test degradation names module_load: {missed:?}"
    );
}

/// Lot 301: every object pinned under the agent's pin directories — the pin
/// root and every directory beside it named after it
/// (`/sys/fs/bpf/northnarrow*`: the start-in-cgroup tracker's, the sysctl
/// judge's, the module files' write history's) — is in the running agent's
/// `OWN_BPF_IDS` with its kind, so the BPF guard refuses a foreign handle on
/// it by id as it does by path (an entry that is not the agent's is named
/// in its foreign-pin WARN instead, never left out in silence); the link
/// self-check expects every pinned link and finds none gone; the cross-view
/// lists none of them as foreign. Lot 300 found the tracker's links pinned
/// beside the root and closed: in neither the guard's ids nor its link
/// views, a root took a handle on one by id. Fails on main (the tracker's
/// links).
#[cfg(feature = "debug-trigger")]
#[test]
fn every_object_pinned_under_the_pin_directories_is_registered_as_the_agent_s() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run as root (sudo -E cargo test …, docs/integration-test-runbook.md)"
    );
    // Declared first: removed after the agent stopped.
    let (installed_agent, _installed_admin) = install_priv_bins();
    let dir = tempfile::tempdir().expect("tempdir");
    let d = dir.path();
    let rules = d.join("combat-rules.v4");
    std::fs::copy(combat_rules_path(), &rules).expect("copy combat rules");
    let state = AgentState::new(d);
    let log_path = d.join("agent.log");
    let log = std::fs::File::create(&log_path).expect("create agent.log");
    let log_err = log.try_clone().expect("clone the log handle");
    let _eni = EniIptablesGuard::install();
    let child = installed_agent
        .command(&state, Launch::Sudo, &[("NO_COLOR", "1")])
        .arg("--combat-rules")
        .arg(&rules)
        .arg("--detect-only")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .expect("spawn northnarrow-agent");
    let _guard = AgentGuard(Some(child));
    let agent_log = || common::strip_ansi(&std::fs::read_to_string(&log_path).unwrap_or_default());
    let tail = |text: String| {
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    };
    let line_with = |needle: &str, within: Duration| {
        common::wait_until(within, || {
            agent_log()
                .lines()
                .find(|l| l.contains(needle))
                .map(str::to_string)
        })
    };

    // 1. Registered, in the fixture's observe mode (the walk below takes
    //    handles on the pins and reads OWN_BPF_IDS); the tracker attached,
    //    or this proves nothing for its links.
    let reg = line_with("own objects registered", SOCKET_POLL_TIMEOUT * 3).unwrap_or_else(|| {
        panic!(
            "no BPF self-defence registration line\n{}",
            tail(agent_log())
        )
    });
    assert!(reg.contains("mode=\"observe\""), "{reg}");
    let armed = line_with("link self-check armed", Duration::from_secs(60))
        .unwrap_or_else(|| panic!("no link self-check armed\n{}", tail(agent_log())));
    assert!(
        agent_log().contains("the start-in-cgroup tracker is attached"),
        "the start-in-cgroup tracker did not attach on this kernel: nothing to check of its \
         links\n{}",
        tail(agent_log())
    );

    // 2. Everything pinned under the pin directories, read by this test.
    let bpffs = Path::new("/sys/fs/bpf");
    let pinned = common::raw_bpf::pinned_under(bpffs, "northnarrow");
    let unread: Vec<String> = pinned
        .iter()
        .filter_map(|(p, o)| o.as_ref().err().map(|e| format!("{}: {e}", p.display())))
        .collect();
    assert!(
        unread.is_empty(),
        "pins this test could not read: {unread:?}"
    );
    let objects: Vec<(PathBuf, u64, u32, u32)> = pinned
        .into_iter()
        .filter_map(|(p, o)| o.ok().map(|(k, id, prog)| (p, k, id, prog)))
        .collect();
    let in_tracker = |p: &Path| {
        p.parent()
            .and_then(Path::file_name)
            .is_some_and(|n| n.to_string_lossy().contains("-cgroup-join-v"))
    };
    let tracker_links: Vec<u32> = objects
        .iter()
        .filter(|(p, k, _, _)| *k == 3 && in_tracker(p))
        .map(|(_, _, id, _)| *id)
        .collect();
    assert!(
        !tracker_links.is_empty(),
        "no link pinned in a tracker directory (/sys/fs/bpf/northnarrow-cgroup-join-v*): {objects:?}"
    );

    // 3. Each in the agent's OWN_BPF_IDS, or named as not its own.
    let own = common::raw_bpf::own_ids()
        .unwrap_or_else(|e| panic!("the agent's OWN_BPF_IDS: {e}\n{}", tail(agent_log())));
    let text = agent_log();
    let reported = |p: &Path| {
        text.lines().any(|l| {
            l.contains("is not one of its objects") && l.contains(&format!("{}:", p.display()))
        })
    };
    let kind = |k: u64| match k {
        1 => "map",
        2 => "program",
        _ => "link",
    };
    let missing: Vec<String> = objects
        .iter()
        .filter(|(p, k, id, _)| !own.contains(&(*k, *id)) && !reported(p))
        .map(|(p, k, id, prog)| format!("{} ({} {id}, program {prog})", p.display(), kind(*k)))
        .collect();
    assert!(
        missing.is_empty(),
        "{} of the {} objects pinned under /sys/fs/bpf/northnarrow* are neither in the agent's \
         OWN_BPF_IDS nor reported as foreign (a root takes a handle on each by id):\n{}",
        missing.len(),
        objects.len(),
        missing.join("\n")
    );
    let unregistered: Vec<&u32> = tracker_links
        .iter()
        .filter(|id| !own.contains(&(3, **id)))
        .collect();
    assert!(
        unregistered.is_empty(),
        "the tracker's links {unregistered:?} are not in OWN_BPF_IDS"
    );

    // 4. The link self-check expects every pinned link of the agent's, and
    //    two rounds later (10 s each, jittered) none is gone.
    let pinned_links = objects.iter().filter(|(_, k, _, _)| *k == 3).count();
    let expected: usize = armed
        .split("links=")
        .nth(1)
        .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no link count in {armed:?}"));
    assert!(
        expected >= pinned_links,
        "the link self-check expects {expected} links, {pinned_links} are pinned: {armed}"
    );
    std::thread::sleep(Duration::from_secs(25));
    let gone: Vec<String> = agent_log()
        .lines()
        .filter(|l| l.contains("own BPF links is GONE"))
        .map(str::to_string)
        .collect();
    assert!(gone.is_empty(), "the link self-check reported: {gone:?}");

    // 5. The cross-view (its status file beside the pid file, a round every
    //    5 s) lists none of the pinned programs or links as foreign.
    let status = state
        .pid_file()
        .parent()
        .expect("the pid file's directory")
        .join("bpf-foreign");
    let body = common::wait_until(Duration::from_secs(30), || {
        std::fs::read_to_string(&status)
            .ok()
            .filter(|b| b.starts_with("# northnarrow-agent pid"))
    })
    .unwrap_or_else(|| {
        panic!(
            "no cross-view status at {}\n{}",
            status.display(),
            tail(agent_log())
        )
    });
    let foreign: Vec<String> = objects
        .iter()
        .filter(|(_, k, _, _)| *k != 1)
        .filter_map(|(p, k, id, _)| {
            let word = if *k == 3 { "link" } else { "prog" };
            body.lines()
                .find(|l| l.starts_with(&format!("{word} {id} ")))
                .map(|l| format!("{}: {l}", p.display()))
        })
        .collect();
    assert!(
        foreign.is_empty(),
        "the cross-view lists pinned objects of the agent's as foreign:\n{}",
        foreign.join("\n")
    );
}
