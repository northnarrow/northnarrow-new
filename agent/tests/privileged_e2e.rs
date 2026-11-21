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
#[cfg(feature = "debug-trigger")]
use northnarrow_agent::anti_tamper::bpf_defense::OWN_IDS_FILE_NAME;

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

/// The ring-drop sampler's journal lines (`nn_linux::sensors::ring_drops::
/// drop_warning`), whatever their message: each carries its counter
/// (`ring=`) and `dropped_since_last_sample=`. The re-check of #565: the
/// review's F4 gave the budgets' and the refused loads' counters their own
/// wording (records HELD BACK, loads REFUSED — no "events DROPPED"), and a
/// filter on the loss message alone found none of them.
#[cfg(feature = "debug-trigger")]
fn ring_drop_lines(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|l| l.contains("dropped_since_last_sample="))
        .collect()
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
    /// Lot 383: the program ids read from the runs' lists so far
    /// ([`Self::note_own_ids`]), which the teardown waits for.
    own_ids_seen: std::sync::Mutex<std::collections::BTreeSet<u32>>,
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
            own_ids_seen: Default::default(),
            agent: installed_agent,
            _installed_admin: installed_admin,
        }
    }

    /// Lot 383: where the runs write the ids of their programs. They are
    /// agents of one directory, so one file: each run's list replaces the
    /// one before.
    fn own_ids_file(&self) -> PathBuf {
        AgentState::new(self.dir.path())
            .pid_file()
            .with_file_name(OWN_IDS_FILE_NAME)
    }

    /// Lot 383: keep the ids the runs' list names now, before a new run
    /// replaces it ([`Self::spawn_as`]) and at the teardown: the teardown
    /// waits for the programs of every run, whoever stopped it.
    fn note_own_ids(&self) {
        let ids = common::our_bpf::ids_in(&[self.own_ids_file()]);
        if let Ok(mut seen) = self.own_ids_seen.lock() {
            seen.extend(ids);
        }
    }

    /// Start the installed agent; `enforce` forces the guard's deny mode.
    fn spawn(&self, name: &'static str, enforce: bool) -> Result<GuardRun, String> {
        self.spawn_as(name, enforce, Launch::Sudo)
    }

    /// [`Self::spawn`], started by `launch`.
    fn spawn_as(
        &self,
        name: &'static str,
        enforce: bool,
        launch: Launch,
    ) -> Result<GuardRun, String> {
        self.note_own_ids();
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
            .command(&state, launch, &env)
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

    /// Lot 374: the enforce run, for its signed stop, with a
    /// trusted-installer window opened on it first ([`TEARDOWN_WINDOW`]):
    /// the window outlives the agent, and in it the teardown removes the
    /// pins its guard keeps ([`purge_pins_in_window`]).
    fn take_for_stop(&mut self) -> Option<GuardRun> {
        let run = self.enforce_run.take()?;
        if let Err(e) = self.grant_window(run.name, TEARDOWN_WINDOW.as_secs() as u32) {
            eprintln!(
                "guard e2e: no teardown window on the {} agent: {e}",
                run.name
            );
        }
        Some(run)
    }
}

/// Lot 374: how long the teardown's window lasts (the signed stop, then the
/// purge).
#[cfg(feature = "debug-trigger")]
const TEARDOWN_WINDOW: Duration = Duration::from_secs(90);

/// Lot 374: the pins an enforce-mode agent's guard keeps after its stop,
/// removed inside the window opened before it (as the lab's
/// `lab_purge_pins` and `install.sh` purge them): the pin root (its lock
/// unmounted first), the tracker's, the judges' and the module history's,
/// then their LSM programs gone. The enforce run's exit vacated its role,
/// and only its unit's restart takes a vacated role (lot 374: in the
/// unit's own cgroup, which no agent a test starts runs in): before, a
/// restore agent started as a transient service put the guard back in
/// observe mode. After the purge the next fixture's agent is a first claim.
///
/// The lab r6 of #582 (ubuntu2604, kernel 7.0, systemd 259): the programs
/// waited for are the stopped agents' own. The ids are those listed in their
/// `bpf-own-ids` files (`own_ids`), as `install.sh --upgrade` and
/// `uninstall.sh` wait for them (external audit DEP-006). The old wait for
/// "no LSM program on the host" never ended where systemd keeps a BPF-LSM
/// program of its own, so the teardown failed after the test had passed.
///
/// Lot 383 (the nightly of 2026-11-21, ubuntu2604 and debian13): with no
/// list given — a test that stopped its enforce run itself took it from the
/// fixture, and the fixture's drop had no run left to name — it still
/// waited for no LSM program at all, PID 1's included. `seen` now carries
/// every id the fixture read from its runs' lists, and the wait is
/// [`common::our_bpf::wait_ours_gone`]: those ids, or, when none was ever
/// readable, our LSM programs by name. Never every LSM program on the host;
/// a program of ours still loaded fails the teardown as before.
#[cfg(feature = "debug-trigger")]
fn purge_pins_in_window(
    own_ids: &[PathBuf],
    seen: &std::collections::BTreeSet<u32>,
) -> Result<(), String> {
    let script = r#"
for i in 1 2 3 4; do
    mountpoint -q /sys/fs/bpf/northnarrow 2>/dev/null || break
    umount /sys/fs/bpf/northnarrow 2>/dev/null || umount -l /sys/fs/bpf/northnarrow 2>/dev/null || break
done
rm -rf /sys/fs/bpf/northnarrow /sys/fs/bpf/northnarrow-sysctl /sys/fs/bpf/northnarrow-module-writes /sys/fs/bpf/northnarrow-cgroup-join-v* 2>/dev/null
rm -f /run/northnarrow/cgroup-join-pins /run/northnarrow/module-writes-pins 2>/dev/null
left=$(ls -d /sys/fs/bpf/northnarrow /sys/fs/bpf/northnarrow-sysctl /sys/fs/bpf/northnarrow-module-writes /sys/fs/bpf/northnarrow-cgroup-join-v* 2>/dev/null)
[ -z "$left" ] || { echo "pins left: $left"; exit 1; }
"#;
    // the lists, read before the pins go (they outlive the agents on purpose)
    let mut ids = seen.clone();
    ids.extend(common::our_bpf::ids_in(own_ids));
    let out = Command::new("sudo")
        .args(["sh", "-c", script, "sh"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("spawn the purge: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "the pin purge failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    common::our_bpf::wait_ours_gone(&ids, PURGE_UNLOAD_TIMEOUT)
        .map_err(|e| format!("the pin purge failed: {e}"))
}

/// Lot 383: how long the purge waits for our programs to unload once the
/// pins are gone (the script's old 20 rounds of 1 s).
#[cfg(feature = "debug-trigger")]
const PURGE_UNLOAD_TIMEOUT: Duration = Duration::from_secs(20);

#[cfg(feature = "debug-trigger")]
impl Drop for GuardFixture {
    fn drop(&mut self) {
        // lot 383: every run's list, whoever stopped it (the runs of one
        // directory write theirs to the same file: [`GuardFixture::note_own_ids`])
        let own_ids = vec![self.own_ids_file()];
        if let Some(mut run) = self.take_for_stop() {
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
        let seen = self
            .own_ids_seen
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default();
        if let Err(e) = purge_pins_in_window(&own_ids, &seen) {
            common::fail_teardown(&format!(
                "guard e2e: the enforce-mode agent's pins could not be removed in the teardown's \
                 window ({e}). The next fixtures' agents (other binaries) are refused their \
                 registration until the pin root is purged or the host restarted (nn-lab.sh: \
                 lab_purge_pins restarts the guest)."
            ));
        }
    }
}

/// The review of #582 (F7): the installed agent unit — its unit file, its
/// binary and `nn-admin` beside it, the bootstrap admin key `install.sh`
/// writes. `None` on a host without an install (the CI guests and the lab
/// install one before the privileged suites).
#[cfg(feature = "debug-trigger")]
struct InstalledUnit {
    nn_admin: PathBuf,
    key: PathBuf,
}

#[cfg(feature = "debug-trigger")]
const AGENT_UNIT: &str = "northnarrow-agent.service";

#[cfg(feature = "debug-trigger")]
fn installed_unit() -> Option<InstalledUnit> {
    let listed = Command::new("systemctl")
        .args(["list-unit-files", AGENT_UNIT, "--no-legend"])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !String::from_utf8_lossy(&listed.stdout).contains(AGENT_UNIT) {
        return None;
    }
    let exec = unit_property("ExecStart");
    let exe = exec
        .split(['{', ';', ' '])
        .find_map(|w| w.strip_prefix("path="))
        .unwrap_or("/usr/local/bin/northnarrow-agent")
        .to_string();
    let nn_admin = Path::new(&exe).with_file_name("nn-admin");
    let key = ["/root/northnarrow-admin.key", "/etc/northnarrow/admin.key"]
        .into_iter()
        .map(PathBuf::from)
        .find(|k| k.exists())?;
    nn_admin.exists().then_some(InstalledUnit { nn_admin, key })
}

#[cfg(feature = "debug-trigger")]
fn unit_property(p: &str) -> String {
    Command::new("systemctl")
        .args(["show", "-p", p, "--value", AGENT_UNIT])
        .stdin(Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

#[cfg(feature = "debug-trigger")]
fn main_pid() -> u32 {
    unit_property("MainPID").parse().unwrap_or(0)
}

#[cfg(feature = "debug-trigger")]
fn unit_active() -> bool {
    unit_property("ActiveState") == "active"
}

#[cfg(feature = "debug-trigger")]
fn systemctl(args: &[&str]) -> std::process::Output {
    Command::new("timeout")
        .arg("200")
        .arg("systemctl")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("spawn systemctl")
}

/// The agent `pid`'s journal (its unit's log namespace), one string.
#[cfg(feature = "debug-trigger")]
fn agent_journal(pid: u32) -> String {
    Command::new("journalctl")
        .args(["--namespace=northnarrow", "-o", "cat", "--no-pager"])
        .arg(format!("_PID={pid}"))
        .stdin(Stdio::null())
        .output()
        .map(|o| without_colours(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default()
}

/// `s` without its terminal colour sequences (`ESC [ … letter`): the fmt
/// layer may colour its fields.
#[cfg(feature = "debug-trigger")]
fn without_colours(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\x1b' && it.peek() == Some(&'[') {
            it.next();
            for d in it.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// The agent unit's last journal lines (its log namespace).
#[cfg(feature = "debug-trigger")]
fn unit_journal_tail() -> String {
    Command::new("journalctl")
        .args([
            "--namespace=northnarrow",
            "-o",
            "cat",
            "--no-pager",
            "-n",
            "60",
            "-u",
            AGENT_UNIT,
        ])
        .stdin(Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// A trusted-installer window of `secs` on the installed agent.
#[cfg(feature = "debug-trigger")]
fn grant_installed_window(u: &InstalledUnit, secs: u32) -> Result<(), String> {
    let out = Command::new(&u.nn_admin)
        .arg("trusted-installer-grant")
        .arg("--key")
        .arg(&u.key)
        .arg("--window-secs")
        .arg(secs.to_string())
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("spawn nn-admin: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "trusted-installer-grant: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

/// The words of a pinned `Array<u32>` under the agent's pin root, by slot —
/// through a read-only descriptor ([`common::raw_bpf::pinned_words`]): the
/// enforce-mode guard refuses `bpftool`'s read-write one even in a window.
#[cfg(feature = "debug-trigger")]
fn pinned_words(name: &str) -> Result<Vec<u32>, String> {
    common::raw_bpf::pinned_words(
        &Path::new(northnarrow_agent::anti_tamper::DEFAULT_BPFFS_ROOT).join(name),
    )
}

/// The review of #582 (F7): the test's installed agent stopped and its pins
/// removed whatever happened — inside a window, as the lab's
/// `lab_purge_pins` does — and the service manager's variable unset.
#[cfg(feature = "debug-trigger")]
struct InstalledRun<'a>(&'a InstalledUnit);

#[cfg(feature = "debug-trigger")]
impl Drop for InstalledRun<'_> {
    fn drop(&mut self) {
        let _ = systemctl(&[
            "unset-environment",
            northnarrow_agent::anti_tamper::bpf_defense::ENFORCE_ENV,
        ]);
        if unit_active() {
            if let Err(e) = grant_installed_window(self.0, 120) {
                eprintln!("unit restart e2e: no teardown window: {e}");
            }
            let _ = systemctl(&["kill", "-s", "SIGTERM", AGENT_UNIT]);
            let until = Instant::now() + Duration::from_secs(30);
            while unit_active() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(500));
            }
        }
        let _ = systemctl(&["reset-failed", AGENT_UNIT]);
        // the unit's agent writes its list beside its pid file
        let own_ids = [Path::new("/run/northnarrow").join(OWN_IDS_FILE_NAME)];
        if let Err(e) = purge_pins_in_window(&own_ids, &Default::default()) {
            common::fail_teardown(&format!(
                "unit restart e2e: the installed agent's pins could not be removed ({e}): the \
                 next suites' agents are refused until the pin root is purged"
            ));
        }
    }
}

/// The review of #582 (F7): the availability side of the vacated role —
/// after its holder exits, the restart of the agent's unit takes the role
/// back while the BPF guard enforces (lot 374 binds the role to that
/// restart: PID 1's child, in the unit's own cgroup, clean marks). The
/// installed agent is started in enforce mode, stopped inside a signed
/// window (its role vacated; the kernel marks the exit in-window), then its
/// unit is started again outside the window: the new agent runs on, in
/// enforce mode, and holds the role (`ROLE_TGIDS`), while `ROLE_MARKS` keeps
/// "vacated this boot, last exit in a window" — what the other role reads.
/// Needs the install (the CI guests' and the lab's); says so and returns
/// without one.
#[cfg(feature = "debug-trigger")]
#[test]
fn a_unit_restart_takes_the_vacated_role_under_enforce() {
    assert_eq!(unsafe { libc::geteuid() }, 0, "run as root");
    common::require_bpftool();
    let Some(unit) = installed_unit() else {
        eprintln!(
            "unit restart e2e: not applicable here — no installed {AGENT_UNIT} (the CI guests \
             and the lab install one before the privileged suites)"
        );
        return;
    };
    assert!(
        !unit_active(),
        "the installed agent must be stopped before this test (nn-lab.sh test-ignored stops it)"
    );
    let _run = InstalledRun(&unit);
    let env = format!(
        "{}=1",
        northnarrow_agent::anti_tamper::bpf_defense::ENFORCE_ENV
    );
    let o = systemctl(&["set-environment", &env]);
    assert!(o.status.success(), "set-environment: {o:?}");

    // 1. The first claim this boot, in enforce mode.
    let o = systemctl(&["start", AGENT_UNIT]);
    assert!(o.status.success(), "the first start: {o:?}");
    let first = main_pid();
    assert!(first > 0 && unit_active(), "no agent after the first start");
    let until = Instant::now() + Duration::from_secs(90);
    let mut log = String::new();
    while Instant::now() < until {
        log = agent_journal(first);
        if log.contains("own objects registered") {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    let reg = log
        .lines()
        .find(|l| l.contains("own objects registered"))
        .unwrap_or_else(|| panic!("no registration line of the first agent:\n{log}"));
    assert!(
        reg.contains("mode=\"enforce\""),
        "the guard does not enforce: {reg}"
    );

    // 2. Its role vacated: stopped inside a signed window. Lot 377: the
    // registration is logged at the anti-tamper's attach, before the FIM,
    // the network and the admin socket start — the grant waits for the
    // socket (it failed once on a slow runner: "connecting to
    // /run/northnarrow/admin.sock: No such file or directory").
    let until = Instant::now() + Duration::from_secs(90);
    while Instant::now() < until && !log.contains("admin socket listening") {
        std::thread::sleep(Duration::from_secs(1));
        log = agent_journal(first);
    }
    assert!(
        log.contains("admin socket listening"),
        "the first agent's admin socket did not come up:\n{log}"
    );
    grant_installed_window(&unit, 15).unwrap_or_else(|e| panic!("{e}"));
    let granted = Instant::now();
    let o = systemctl(&["kill", "-s", "SIGTERM", AGENT_UNIT]);
    assert!(o.status.success(), "kill in the window: {o:?}");
    let until = Instant::now() + Duration::from_secs(30);
    while unit_active() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(!unit_active(), "the agent did not stop inside the window");

    // 3. Outside the window, the unit's restart takes the vacated role.
    let left = Duration::from_secs(20).saturating_sub(granted.elapsed());
    std::thread::sleep(left);
    let o = systemctl(&["start", AGENT_UNIT]);
    assert!(
        o.status.success(),
        "the unit's restart was refused the vacated role under enforce: {o:?}\n{}",
        unit_journal_tail()
    );
    let second = main_pid();
    assert!(
        second > 0 && second != first,
        "no new agent ({first} → {second})"
    );
    std::thread::sleep(Duration::from_secs(10));
    assert!(
        unit_active() && main_pid() == second,
        "the successor did not stay up:\n{}",
        agent_journal(second)
    );
    let log = agent_journal(second);
    let reg = log
        .lines()
        .find(|l| l.contains("own objects registered"))
        .unwrap_or_else(|| panic!("no registration line of the successor:\n{log}"));
    assert!(
        reg.contains("mode=\"enforce\""),
        "the successor's guard: {reg}"
    );
    assert!(
        !log.contains("role NOT recorded"),
        "the successor did not record its role:\n{log}"
    );

    // 4. Read in a window, through read-only descriptors (a write handle
    // stays refused there while the guard enforces): the successor holds the
    // agent's slot; the kernel's mark of the vacancy outlived the claim.
    // (Lot 377: once the successor's admin socket is up, as in step 2.)
    let until = Instant::now() + Duration::from_secs(90);
    let mut log = log;
    while Instant::now() < until && !log.contains("admin socket listening") {
        std::thread::sleep(Duration::from_secs(1));
        log = agent_journal(second);
    }
    assert!(
        log.contains("admin socket listening"),
        "the successor's admin socket did not come up:\n{log}"
    );
    grant_installed_window(&unit, 120).unwrap_or_else(|e| panic!("{e}"));
    let roles = pinned_words("ROLE_TGIDS").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        roles.get(1).copied(),
        Some(second),
        "ROLE_TGIDS[agent] is not the successor: {roles:?}"
    );
    let marks = pinned_words("ROLE_MARKS").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        marks.get(1).copied(),
        Some(common_wire_mark_in_window()),
        "ROLE_MARKS[agent] after a stop inside a window: {marks:?}"
    );
}

/// `role_exit`'s mark of an exit inside a window.
#[cfg(feature = "debug-trigger")]
fn common_wire_mark_in_window() -> u32 {
    antitamper_bpf::ROLE_MARK_VACATED | antitamper_bpf::ROLE_MARK_IN_WINDOW
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

    // 6. The authorised stop: a 2-of-N signed shutdown. Drop then removes
    //    its pins in the window opened before it (lot 374).
    let mut run = fx.take_for_stop().expect("enforce run");
    if let Err(e) =
        common::shutdown_signed(&mut run.child, &fx.signed(&run.socket), GUARD_STOP_TIMEOUT)
    {
        let tail = log_tail(&run.log);
        fx.enforce_run = Some(run);
        panic!("signed shutdown of the enforce-mode agent failed: {e}\n{tail}");
    }
}

// ── Lot 318 — external bug hunt BUG37: the BPF guard's refusals ─────────

/// A process of `nobody` with `CAP_SYS_ADMIN` and `CAP_BPF` (the two that
/// reach `bpf()`'s LSM hook past `unprivileged_bpf_disabled`), pinned to
/// `cpu`, asking for a handle on map `map_id` until CLOCK_MONOTONIC passes
/// `until`. Forked from this multi-threaded test: the child makes raw
/// system calls only (one thread: each `set*id` its own) and `_exit`s.
/// Exit 0: every request refused; 1: a handle was granted; 2..5: a step of
/// the drop failed.
#[cfg(feature = "debug-trigger")]
fn fork_handle_flooder(cpu: usize, map_id: u32, until: libc::timespec) -> libc::pid_t {
    /// `struct __user_cap_header_struct` / `__user_cap_data_struct`.
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    const CAP_SYS_ADMIN: u32 = 21;
    const CAP_BPF: u32 = 39;
    const NOBODY: libc::c_long = 65534;
    // SAFETY: the child runs raw system calls on its own stack and ends
    // with `_exit`; the parent only gets the pid.
    unsafe {
        let pid = libc::fork();
        if pid != 0 {
            return pid;
        }
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        if libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0 {
            libc::_exit(2);
        }
        if libc::syscall(libc::SYS_setgroups, 0, std::ptr::null::<libc::gid_t>()) != 0
            || libc::syscall(libc::SYS_setresgid, NOBODY, NOBODY, NOBODY) != 0
        {
            libc::_exit(3);
        }
        if libc::syscall(libc::SYS_setresuid, NOBODY, NOBODY, NOBODY) != 0 {
            libc::_exit(4);
        }
        let header = CapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut data = [CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        for cap in [CAP_SYS_ADMIN, CAP_BPF] {
            let d = &mut data[(cap / 32) as usize];
            d.effective |= 1 << (cap % 32);
            d.permitted |= 1 << (cap % 32);
        }
        if libc::syscall(libc::SYS_capset, &header as *const CapHeader, data.as_ptr()) != 0 {
            libc::_exit(5);
        }
        let mut granted = 0;
        let mut attr = [0u32; 32];
        let mut now: libc::timespec = std::mem::zeroed();
        loop {
            for _ in 0..256 {
                attr[0] = map_id;
                let fd = libc::syscall(
                    libc::SYS_bpf,
                    ::common::bpf_cmd::BPF_MAP_GET_FD_BY_ID as libc::c_long,
                    attr.as_mut_ptr(),
                    std::mem::size_of_val(&attr) as u32,
                );
                if fd >= 0 {
                    granted = 1;
                    libc::close(fd as i32);
                }
            }
            libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now);
            if (now.tv_sec, now.tv_nsec) >= (until.tv_sec, until.tv_nsec) {
                libc::_exit(granted);
            }
        }
    }
}

/// External bug hunt BUG37, the residue lot 293 left (lot 318): a loop of
/// refused handles on one of the agent's maps, on every CPU, must not cost
/// the record of a refused `kill`. The BPF guard's refusals wrote the
/// shared denial ring with no budget, and such a loop filled it: the kill
/// was refused, its record lost (counted as an `fs_protect` drop). Behind
/// the per-attempt budget now, the loop's records are held back
/// (`denial_rate`) and the kills' arrive. The loop runs as `nobody` with
/// the two capabilities (its NN-L-AT-001 budget is its uid's, not root's);
/// each kill is a process of its own (the task denials' dedup is per
/// caller).
#[cfg(feature = "debug-trigger")]
#[test]
fn a_bpf_handle_loop_does_not_bury_a_refused_kill() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run as root (sudo -E cargo test …, docs/integration-test-runbook.md)"
    );
    let _eni = EniIptablesGuard::install();
    let mut fx = GuardFixture::new();
    let run = fx.spawn("flood", true).unwrap_or_else(|e| panic!("{e}"));
    let run = fx.enforce_run.insert(run);
    let agent = wait_ready(run).unwrap_or_else(|e| panic!("{e}"));
    let log = run.log.clone();
    let reg = wait_for_log_line(&log, &["own objects registered"], GUARD_LOG_TIMEOUT)
        .unwrap_or_else(|| panic!("no BPF self-defence registration line\n{}", log_tail(&log)));
    assert!(
        reg.contains("mode=\"enforce\""),
        "the guard did not start in enforce mode: {reg}"
    );

    // One of the agent's maps, read in a window (outside one a read
    // handle on its maps is refused too).
    const WINDOW_SECS: u32 = 5;
    fx.grant_window("flood", WINDOW_SECS)
        .unwrap_or_else(|e| panic!("{e}\n{}", log_tail(&log)));
    let map_id = common::raw_bpf::own_ids()
        .unwrap_or_else(|e| panic!("the agent's own ids: {e}\n{}", log_tail(&log)))
        .into_iter()
        .find_map(|(kind, id)| (kind == 1).then_some(id))
        .expect("OWN_BPF_IDS lists none of the agent's maps");
    std::thread::sleep(Duration::from_secs(u64::from(WINDOW_SECS) + 2));

    // The loop: every CPU, 4 s.
    const FLOOD: Duration = Duration::from_secs(4);
    let cpus = std::thread::available_parallelism()
        .map_or(2, |n| n.get())
        .min(8);
    let mut until: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut until) };
    until.tv_sec += FLOOD.as_secs() as libc::time_t;
    let started = Instant::now();
    let flooders: Vec<libc::pid_t> = (0..cpus)
        .map(|cpu| fork_handle_flooder(cpu, map_id, until))
        .collect();
    assert!(flooders.iter().all(|p| *p > 0), "fork failed: {flooders:?}");

    // In the middle of it, five refused kills, each its own process.
    let mut killers = Vec::new();
    for k in 0..5u64 {
        let at = Duration::from_millis(1000 + 500 * k);
        if let Some(wait) = at.checked_sub(started.elapsed()) {
            std::thread::sleep(wait);
        }
        let mut kill = Command::new("kill")
            .args(["-9", &agent.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn kill");
        let id = kill.id();
        let st = kill.wait().expect("wait kill");
        assert!(
            !st.success(),
            "kill -9 of the agent (pid {agent}) was not refused"
        );
        killers.push(id);
    }
    for pid in &flooders {
        let mut status = 0;
        // SAFETY: our own child.
        let r = unsafe { libc::waitpid(*pid, &mut status, 0) };
        assert_eq!(r, *pid, "waitpid {pid}");
        let code = libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status));
        match code {
            Some(0) => {}
            Some(1) => panic!(
                "a handle on the agent's map {map_id} was granted to nobody with CAP_BPF in enforce \
                 mode\n{}",
                log_tail(&log)
            ),
            other => panic!("the flooder {pid} could not drop to nobody with CAP_BPF: {other:?}"),
        }
    }
    let flood_end = Instant::now();
    let alive = matches!(
        fx.enforce_run
            .as_mut()
            .expect("enforce run")
            .child
            .try_wait(),
        Ok(None)
    );
    assert!(alive, "the agent is gone after the refused kills");

    // Every kill's record arrived.
    for k in &killers {
        let pid = format!("pid={k} ");
        assert!(
            wait_for_log_line(
                &log,
                &["ANTI-TAMPER DENIAL", &pid, "op=signal"],
                Duration::from_secs(15)
            )
            .is_some(),
            "the refused kill of process {k} left no record (killers {killers:?}, map {map_id}, \
             {cpus} flooders)\n{}",
            log_tail(&log)
        );
    }
    // The ring-drop sampler's round (every 10 s) after the loop: the loop
    // was held back by the budget, and the ring never filled.
    let sampled = flood_end + Duration::from_secs(12);
    if let Some(wait) = sampled.checked_duration_since(Instant::now()) {
        std::thread::sleep(wait);
    }
    let text = read_agent_log(&log);
    let drops = ring_drop_lines(&text);
    assert!(
        !drops.iter().any(|l| l.contains("fs_protect")),
        "the denial ring filled during the loop: {drops:#?}"
    );
    assert!(
        drops.iter().any(|l| l.contains("denial_rate")),
        "the loop's refusals were not held back by the attempt budget (no denial_rate drop: did \
         it run?): {drops:#?}\n{}",
        log_tail(&log)
    );

    // The authorised stop, signed; Drop removes the pins in its window.
    let mut run = fx.take_for_stop().expect("enforce run");
    if let Err(e) =
        common::shutdown_signed(&mut run.child, &fx.signed(&run.socket), GUARD_STOP_TIMEOUT)
    {
        let tail = log_tail(&run.log);
        fx.enforce_run = Some(run);
        panic!("signed shutdown of the enforce-mode agent failed: {e}\n{tail}");
    }
}

/// Lot 318 (the review of #545, F1): a loop of refused handles on one of
/// the agent's maps — non-decisive refusals, the kind an administrator's
/// `bpftool map list` makes — on one CPU, and in the middle of it, on that
/// CPU, a refused new entry in `/etc/northnarrow` (a protected directory of
/// every agent, `PROTECTED_DIR_FLAGS`): decisive, signed at each attempt as
/// a protected file's unlink is. The two shared one per-CPU budget, and 50
/// handles in a second held back the refusal's record, the posture's
/// decisive trigger with it (it stayed at ENGAGED). Now the non-decisive
/// refusals spend a budget of their own (`minor_denial_rate`): the `mkdir`
/// is refused, its record arrives, the posture reaches COMBAT by
/// `AntiTamperDenial`, and the loop's records past their budget are
/// counted. (A first version unlinked the fixture agent's signing key in
/// its tempdir: no agent protects that path, and the unlink went through —
/// 7.0 lab, round r5.)
#[cfg(feature = "debug-trigger")]
#[test]
fn a_bpf_handle_loop_does_not_hide_a_decisive_refusal() {
    use std::os::unix::process::CommandExt;
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run as root (sudo -E cargo test …, docs/integration-test-runbook.md)"
    );
    let _eni = EniIptablesGuard::install();
    let mut fx = GuardFixture::new();
    let run = fx.spawn("minor", true).unwrap_or_else(|e| panic!("{e}"));
    let run = fx.enforce_run.insert(run);
    wait_ready(run).unwrap_or_else(|e| panic!("{e}"));
    let log = run.log.clone();
    let reg = wait_for_log_line(&log, &["own objects registered"], GUARD_LOG_TIMEOUT)
        .unwrap_or_else(|| panic!("no BPF self-defence registration line\n{}", log_tail(&log)));
    assert!(
        reg.contains("mode=\"enforce\""),
        "the guard did not start in enforce mode: {reg}"
    );
    let etc = Path::new("/etc/northnarrow");
    assert!(
        etc.is_dir(),
        "the agent's protected directory {}",
        etc.display()
    );
    let target = etc.join(".nn-e2e-318-minor");

    const WINDOW_SECS: u32 = 5;
    fx.grant_window("minor", WINDOW_SECS)
        .unwrap_or_else(|e| panic!("{e}\n{}", log_tail(&log)));
    // a leftover of an earlier failed run, removed inside the window
    let _ = std::fs::remove_dir(&target);
    let map_id = common::raw_bpf::own_ids()
        .unwrap_or_else(|e| panic!("the agent's own ids: {e}\n{}", log_tail(&log)))
        .into_iter()
        .find_map(|(kind, id)| (kind == 1).then_some(id))
        .expect("OWN_BPF_IDS lists none of the agent's maps");
    std::thread::sleep(Duration::from_secs(u64::from(WINDOW_SECS) + 2));

    // The loop on CPU 0, 3 s: far past the 50 records a second its budget
    // has there.
    let mut until: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut until) };
    until.tv_sec += 3;
    let flooder = fork_handle_flooder(0, map_id, until);
    assert!(flooder > 0, "fork failed");
    std::thread::sleep(Duration::from_millis(1000));
    // On the same CPU, the decisive refusal: a new entry in the agent's
    // protected directory (python3 prints the errno itself: uutils' mkdir
    // says "Permission denied" for EPERM too). Its own process group: the
    // ladder a refusal raises acts on the actor, never the harness.
    let actor = Command::new("taskset")
        .args(["-c", "0", "python3", "-I", "-c"])
        .arg(
            "import errno, os, sys\n\
             try:\n    os.mkdir(sys.argv[1])\n    print('ok')\n\
             except OSError as e:\n    print('errno=' + errno.errorcode.get(e.errno, str(e.errno)))",
        )
        .arg(&target)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("spawn taskset python3");
    let actor_pid = actor.id();
    let out = actor.wait_with_output().expect("wait for the actor");
    let mut status = 0;
    // SAFETY: our own child.
    assert_eq!(unsafe { libc::waitpid(flooder, &mut status, 0) }, flooder);
    match libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status)) {
        Some(0) => {}
        Some(1) => panic!("a handle on the agent's map {map_id} was granted in enforce mode"),
        other => panic!("the flooder could not drop to nobody with CAP_BPF: {other:?}"),
    }
    let said = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let made = target.exists();
    if made {
        // not refused: put the directory back as it was (the test fails)
        let _ = std::fs::remove_dir(&target);
    }
    assert!(
        said == "errno=EPERM" && !made,
        "the new entry {} was not refused: {said:?} {}",
        target.display(),
        String::from_utf8_lossy(&out.stderr)
    );

    // its record arrived (taskset execs python3 in place: the pid is the
    // actor's) …
    let pid = format!("pid={actor_pid} ");
    let line = wait_for_log_line(
        &log,
        &["ANTI-TAMPER DENIAL", &pid, "op=mkdir"],
        Duration::from_secs(15),
    );
    assert!(
        line.is_some(),
        "the refused mkdir (pid {actor_pid}) left no record behind the handle loop on its CPU\n{}",
        log_tail(&log)
    );
    // … and the posture took it as what it is: decisive
    assert!(
        wait_for_log_line(
            &log,
            &["POSTURE TRANSITION", "AntiTamperDenial"],
            Duration::from_secs(15)
        )
        .is_some(),
        "no COMBAT by AntiTamperDenial after the refused mkdir\n{}",
        log_tail(&log)
    );
    // the loop's records past their own budget were counted (the sampler's
    // round, every 10 s), and none of the decisive budget's
    std::thread::sleep(Duration::from_secs(12));
    let text = read_agent_log(&log);
    let drops = ring_drop_lines(&text);
    assert!(
        drops.iter().any(|l| l.contains("minor_denial_rate")),
        "the handle loop was not held back by its own budget: {drops:#?}"
    );
    assert!(
        !drops
            .iter()
            .any(|l| l.contains("fs_protect") || l.contains("\"denial_rate\"")),
        "a decisive record or the ring lost: {drops:#?}"
    );

    let mut run = fx.take_for_stop().expect("enforce run");
    if let Err(e) =
        common::shutdown_signed(&mut run.child, &fx.signed(&run.socket), GUARD_STOP_TIMEOUT)
    {
        let tail = log_tail(&run.log);
        fx.enforce_run = Some(run);
        panic!("signed shutdown of the enforce-mode agent failed: {e}\n{tail}");
    }
}

/// Lot 356 (pre-alpha F3-8): `n` loads, on CPU `cpu`, in a child of its
/// own process group, of a kprobe program that calls `bpf_send_signal` —
/// the content judge refuses it outside a trusted-installer window and
/// holds it inside one. The ids of the programs loaded (the descriptors
/// closed at once: no program outlives the window), and the errno of each
/// load refused.
#[cfg(feature = "debug-trigger")]
fn fork_held_loads(cpu: usize, n: usize) -> (Vec<u32>, Vec<i32>) {
    /// `struct bpf_insn` as one word: code, regs, off, imm.
    const fn insn(code: u8, dst: u8, imm: i32) -> u64 {
        code as u64 | (dst as u64) << 8 | (imm as u32 as u64) << 32
    }
    const BPF_PROG_TYPE_KPROBE: u32 = 2;
    const BPF_FUNC_SEND_SIGNAL: i32 = 109;
    let prog: [u64; 4] = [
        insn(0xb7, 1, libc::SIGUSR1), // r1 = SIGUSR1
        insn(0x85, 0, BPF_FUNC_SEND_SIGNAL),
        insn(0xb7, 0, 0), // r0 = 0
        insn(0x95, 0, 0), // exit
    ];
    let license = *b"GPL\0";
    assert!(n <= 512, "at most 512 loads");
    let mut fds = [0i32; 2];
    // SAFETY: a valid out-array of two descriptors.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let mut out = vec![0i32; 2 * n];
    // SAFETY: the child makes raw system calls on buffers allocated before
    // the fork, and ends with `_exit`; the parent reads the pipe.
    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            libc::close(fds[0]);
            libc::setpgid(0, 0);
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_SET(cpu, &mut set);
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
            let mut loaded = [0i32; 512];
            for i in 0..n {
                let mut attr = [0u32; 32];
                attr[0] = BPF_PROG_TYPE_KPROBE;
                attr[1] = prog.len() as u32;
                let insns = prog.as_ptr() as u64;
                attr[2] = insns as u32;
                attr[3] = (insns >> 32) as u32;
                let lic = license.as_ptr() as u64;
                attr[4] = lic as u32;
                attr[5] = (lic >> 32) as u32;
                // prog_name (byte 48)
                attr[12] = u32::from_le_bytes(*b"nn_h");
                attr[13] = u32::from_le_bytes(*b"eld\0");
                let fd = libc::syscall(
                    libc::SYS_bpf,
                    ::common::bpf_cmd::BPF_PROG_LOAD as libc::c_long,
                    attr.as_mut_ptr(),
                    std::mem::size_of_val(&attr) as u32,
                );
                if fd < 0 {
                    out[n + i] = *libc::__errno_location();
                    continue;
                }
                loaded[i] = fd as i32;
                // struct bpf_prog_info: type, then id
                let mut info = [0u32; 32];
                let mut a = [0u32; 32];
                a[0] = fd as u32;
                a[1] = std::mem::size_of_val(&info) as u32;
                let p = info.as_mut_ptr() as u64;
                a[2] = p as u32;
                a[3] = (p >> 32) as u32;
                if libc::syscall(
                    libc::SYS_bpf,
                    ::common::bpf_cmd::BPF_OBJ_GET_INFO_BY_FD as libc::c_long,
                    a.as_mut_ptr(),
                    std::mem::size_of_val(&a) as u32,
                ) == 0
                {
                    out[i] = info[1] as i32;
                }
            }
            for fd in &loaded[..n] {
                if *fd > 0 {
                    libc::close(*fd);
                }
            }
            let bytes = std::mem::size_of_val(&out[..]);
            let w = libc::write(fds[1], out.as_ptr() as *const libc::c_void, bytes);
            libc::_exit(if w == bytes as isize { 0 } else { 9 });
        }
        libc::close(fds[1]);
        let mut status = 0;
        let bytes = std::mem::size_of_val(&out[..]);
        let mut got = 0usize;
        while got < bytes {
            let r = libc::read(
                fds[0],
                (out.as_mut_ptr() as *mut u8).add(got) as *mut libc::c_void,
                bytes - got,
            );
            if r <= 0 {
                break;
            }
            got += r as usize;
        }
        libc::close(fds[0]);
        assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 && got == bytes,
            "the loader child: status {status}, {got} of {bytes} bytes"
        );
    }
    let ids = out[..n]
        .iter()
        .filter(|id| **id > 0)
        .map(|id| *id as u32)
        .collect();
    let refused = out[n..].iter().filter(|e| **e != 0).copied().collect();
    (ids, refused)
}

/// Lot 356 (pre-alpha F3-8): a window's held load — a program the content
/// judge refuses outside a trusted-installer window, loaded inside one and
/// held — was signed through the per-CPU budget of the non-decisive
/// refusals. A flood of them on a CPU (here refused handles on one of the
/// agent's maps, as the lab's refused uses of a held program did) spent it,
/// and a window load on that CPU in the same second was held, its record a
/// `minor_denial_rate` count naming no program: the lab lost it 1 time in
/// 3 on 6.8. A sole trace now, it spends no budget: 64 such loads on that
/// CPU at once (past the 50 a second the budget has, whatever the flood
/// left of it) are each held and signed, naming their program, and none is
/// refused for want of room.
#[cfg(feature = "debug-trigger")]
#[test]
fn a_flood_of_minor_refusals_never_hides_a_held_load() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run as root (sudo -E cargo test …, docs/integration-test-runbook.md)"
    );
    let _eni = EniIptablesGuard::install();
    let mut fx = GuardFixture::new();
    let run = fx.spawn("held", true).unwrap_or_else(|e| panic!("{e}"));
    let run = fx.enforce_run.insert(run);
    wait_ready(run).unwrap_or_else(|e| panic!("{e}"));
    let log = run.log.clone();
    let reg = wait_for_log_line(&log, &["own objects registered"], GUARD_LOG_TIMEOUT)
        .unwrap_or_else(|| panic!("no BPF self-defence registration line\n{}", log_tail(&log)));
    assert!(
        reg.contains("mode=\"enforce\""),
        "the guard did not start in enforce mode: {reg}"
    );
    // One of the agent's maps, read in a window (outside one a read handle
    // on its maps is refused too), then the window let close.
    const ID_WINDOW_SECS: u32 = 5;
    fx.grant_window("held", ID_WINDOW_SECS)
        .unwrap_or_else(|e| panic!("{e}\n{}", log_tail(&log)));
    let map_id = common::raw_bpf::own_ids()
        .unwrap_or_else(|e| panic!("the agent's own ids: {e}\n{}", log_tail(&log)))
        .into_iter()
        .find_map(|(kind, id)| (kind == 1).then_some(id))
        .expect("OWN_BPF_IDS lists none of the agent's maps");
    std::thread::sleep(Duration::from_secs(u64::from(ID_WINDOW_SECS) + 2));
    // outside a window, the content judge refuses the program
    let (ids, refused) = fork_held_loads(0, 1);
    assert!(
        ids.is_empty() && refused == [libc::EPERM],
        "a kprobe calling bpf_send_signal loaded outside a window: {ids:?} {refused:?}"
    );

    // The flood on CPU 0, 1.5 s: far past the 50 records a second its
    // budget has there; it ends before the window (inside one, a write
    // handle is refused as decisive).
    let mut until: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut until) };
    until.tv_nsec += 500_000_000;
    until.tv_sec += 1 + until.tv_nsec / 1_000_000_000;
    until.tv_nsec %= 1_000_000_000;
    let flooder = fork_handle_flooder(0, map_id, until);
    assert!(flooder > 0, "fork failed");
    let mut status = 0;
    // SAFETY: our own child.
    assert_eq!(unsafe { libc::waitpid(flooder, &mut status, 0) }, flooder);
    match libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status)) {
        Some(0) => {}
        Some(1) => panic!("a handle on the agent's map {map_id} was granted in enforce mode"),
        other => panic!("the flooder could not drop to nobody with CAP_BPF: {other:?}"),
    }
    // At once the window, and on CPU 0 the loads: 64, in well under the
    // second the flood's budget window has left.
    const HELD: usize = 64;
    fx.grant_window("held", 10)
        .unwrap_or_else(|e| panic!("{e}\n{}", log_tail(&log)));
    let (ids, refused) = fork_held_loads(0, HELD);
    assert!(
        refused.is_empty() && ids.len() == HELD,
        "window loads refused: {refused:?} ({} loaded)\n{}",
        ids.len(),
        log_tail(&log)
    );
    // every one held and signed, naming its program — at its load (the
    // `target_dev`'s use is 0), not found later outliving the window
    for id in &ids {
        let needle = format!("prog_id={id} ");
        let line = wait_for_log_line(&log, &["BPF HELD", &needle], Duration::from_secs(20))
            .unwrap_or_else(|| {
                panic!(
                    "the held load of program {id} left no record behind the flood on its CPU\n{}",
                    log_tail(&log)
                )
            });
        let dev: u64 = line
            .split("target_dev=")
            .nth(1)
            .and_then(|r| r.split_whitespace().next())
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("no target_dev in {line}"));
        assert_eq!(
            ::common::wire::bpf_held_of(dev).0,
            0,
            "program {id}'s record is not its load's: {line}"
        );
    }
    // the flood was held back in its own budget; no held load was refused
    // for want of room, and the ring lost nothing (the sampler's round,
    // every 10 s)
    std::thread::sleep(Duration::from_secs(12));
    let text = read_agent_log(&log);
    let drops = ring_drop_lines(&text);
    assert!(
        drops.iter().any(|l| l.contains("minor_denial_rate")),
        "the flood was not held back by its own budget: {drops:#?}"
    );
    assert!(
        !drops
            .iter()
            .any(|l| l.contains("held_load_unsigned") || l.contains("fs_protect")),
        "a held load refused unsigned, or the ring lost: {drops:#?}"
    );

    let mut run = fx.take_for_stop().expect("enforce run");
    if let Err(e) =
        common::shutdown_signed(&mut run.child, &fx.signed(&run.socket), GUARD_STOP_TIMEOUT)
    {
        let tail = log_tail(&run.log);
        fx.enforce_run = Some(run);
        panic!("signed shutdown of the enforce-mode agent failed: {e}\n{tail}");
    }
}

/// The re-check of #545: what a flood of non-decisive records on one CPU
/// left of a decisive one there — its record arrived, the posture took it
/// as `AntiTamperDenial`, the flood was held back in `minor_denial_rate`
/// and nothing in a decisive budget (`budget`) or the ring.
fn assert_decisive_record_after_flood(
    fx: &mut GuardFixture,
    log: &Path,
    actor: u32,
    op: &str,
    budget: &str,
) {
    let pid = format!("pid={actor} ");
    assert!(
        wait_for_log_line(
            log,
            &["ANTI-TAMPER DENIAL", &pid, &format!("op={op}")],
            Duration::from_secs(15)
        )
        .is_some(),
        "the refused {op} (pid {actor}) left no record behind the flood on its CPU\n{}",
        log_tail(log)
    );
    assert!(
        wait_for_log_line(
            log,
            &["POSTURE TRANSITION", "AntiTamperDenial"],
            Duration::from_secs(15)
        )
        .is_some(),
        "no COMBAT by AntiTamperDenial after the refused {op}\n{}",
        log_tail(log)
    );
    // the sampler's round, every 10 s
    std::thread::sleep(Duration::from_secs(12));
    let text = read_agent_log(log);
    let drops = ring_drop_lines(&text);
    assert!(
        drops.iter().any(|l| l.contains("minor_denial_rate")),
        "the flood was not held back by its own budget: {drops:#?}"
    );
    let decisive = format!("\"{budget}\"");
    assert!(
        !drops
            .iter()
            .any(|l| l.contains("fs_protect") || l.contains(&decisive)),
        "a decisive record or the ring lost: {drops:#?}"
    );
    let mut run = fx.take_for_stop().expect("enforce run");
    if let Err(e) =
        common::shutdown_signed(&mut run.child, &fx.signed(&run.socket), GUARD_STOP_TIMEOUT)
    {
        let tail = log_tail(&run.log);
        fx.enforce_run = Some(run);
        panic!("signed shutdown of the enforce-mode agent failed: {e}\n{tail}");
    }
}

/// The re-check of #545 (R1): the kprobes and lockdown switches are
/// refused at the write-open and signed at each attempt, and they are no
/// decisive tamper (`DefenseImpairment`: a debugging script meets them) —
/// yet they spent the decisive attempt budget. 150 refused write-opens of
/// `kprobes/enabled` (or securityfs' `lockdown`) on CPU 0 held back, that
/// second, a refused new entry in `/etc/northnarrow` there: no record, no
/// COMBAT. They spend the non-decisive budget now.
#[cfg(feature = "debug-trigger")]
#[test]
fn a_switch_refusal_loop_does_not_hide_a_decisive_refusal() {
    use std::os::unix::process::CommandExt;
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run as root (sudo -E cargo test …, docs/integration-test-runbook.md)"
    );
    let Some(switch) = [
        "/sys/kernel/debug/kprobes/enabled",
        "/sys/kernel/security/lockdown",
    ]
    .into_iter()
    .find(|p| Path::new(p).exists()) else {
        eprintln!("neither kprobes/enabled nor securityfs' lockdown here: nothing to test");
        return;
    };
    let _eni = EniIptablesGuard::install();
    let mut fx = GuardFixture::new();
    let run = fx.spawn("switch", true).unwrap_or_else(|e| panic!("{e}"));
    let run = fx.enforce_run.insert(run);
    wait_ready(run).unwrap_or_else(|e| panic!("{e}"));
    let log = run.log.clone();
    wait_for_log_line(&log, &["own objects registered"], GUARD_LOG_TIMEOUT)
        .unwrap_or_else(|| panic!("no BPF self-defence registration line\n{}", log_tail(&log)));
    let etc = Path::new("/etc/northnarrow");
    assert!(
        etc.is_dir(),
        "the agent's protected directory {}",
        etc.display()
    );
    let target = etc.join(".nn-e2e-318-switch");
    // a leftover of an earlier failed run, removed inside a window
    const WINDOW_SECS: u32 = 5;
    fx.grant_window("switch", WINDOW_SECS)
        .unwrap_or_else(|e| panic!("{e}\n{}", log_tail(&log)));
    let _ = std::fs::remove_dir(&target);
    std::thread::sleep(Duration::from_secs(u64::from(WINDOW_SECS) + 2));

    // One process on CPU 0: the refused write-opens of the switch, then the
    // decisive refusal, within the second.
    let out = Command::new("taskset")
        .args(["-c", "0", "python3", "-I", "-c"])
        .arg(
            "import errno, os, sys\n\
             refused = 0\n\
             for _ in range(150):\n    \
                 try:\n        os.close(os.open(sys.argv[1], os.O_WRONLY))\n    \
                 except OSError as e:\n        refused += e.errno == errno.EPERM\n\
             try:\n    os.mkdir(sys.argv[2])\n    made = 'ok'\n\
             except OSError as e:\n    made = 'errno=' + errno.errorcode.get(e.errno, str(e.errno))\n\
             print(os.getpid(), refused, made, flush=True)",
        )
        .arg(switch)
        .arg(&target)
        .stdin(Stdio::null())
        .process_group(0)
        .output()
        .expect("run the actor");
    let said = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let made = target.exists();
    if made {
        let _ = std::fs::remove_dir(&target);
    }
    let f: Vec<&str> = said.split_whitespace().collect();
    assert_eq!(
        f.len(),
        3,
        "the actor said {said:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        f[1], "150",
        "the switch {switch} was not refused every time: {said:?}"
    );
    assert!(
        f[2] == "errno=EPERM" && !made,
        "the new entry {} was not refused: {said:?}",
        target.display()
    );
    let actor: u32 = f[0].parse().expect("the actor's pid");
    assert_decisive_record_after_flood(&mut fx, &log, actor, "mkdir", "denial_rate");
}

/// The re-check of #545 (R2): the task denials' budget carried the refused
/// renices (`DefenseImpairment`: a tuning daemon meets them) with the
/// refused signals and ptraces, so 80 short-lived processes each refused a
/// renice of the agent on CPU 0 held back, that second, a refused `kill
/// -9` of the agent there: no record, no COMBAT. A renice spends the
/// non-decisive budget now, after the per-caller dedup; the task budget is
/// the decisive refusals' alone.
#[cfg(feature = "debug-trigger")]
#[test]
fn a_renice_loop_does_not_hide_a_refused_kill() {
    use std::os::unix::process::CommandExt;
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run as root (sudo -E cargo test …, docs/integration-test-runbook.md)"
    );
    let _eni = EniIptablesGuard::install();
    let mut fx = GuardFixture::new();
    let run = fx.spawn("renice", true).unwrap_or_else(|e| panic!("{e}"));
    let run = fx.enforce_run.insert(run);
    let agent = wait_ready(run).unwrap_or_else(|e| panic!("{e}"));
    let log = run.log.clone();
    wait_for_log_line(&log, &["own objects registered"], GUARD_LOG_TIMEOUT)
        .unwrap_or_else(|| panic!("no BPF self-defence registration line\n{}", log_tail(&log)));

    // A parent on CPU 0 (its children inherit it): 80 children, each one
    // refused renice of the agent (one record each: the dedup is per
    // caller), then its own `kill -9` of the agent.
    let out = Command::new("taskset")
        .args(["-c", "0", "python3", "-I", "-c"])
        .arg(
            "import errno, os, sys\n\
             agent = int(sys.argv[1])\n\
             refused = 0\n\
             for _ in range(80):\n    \
                 pid = os.fork()\n    \
                 if pid == 0:\n        \
                     try:\n            os.setpriority(os.PRIO_PROCESS, agent, 19)\n            os._exit(0)\n        \
                     except OSError as e:\n            os._exit(1 if e.errno == errno.EPERM else 2)\n    \
                 _, st = os.waitpid(pid, 0)\n    \
                 refused += os.WIFEXITED(st) and os.WEXITSTATUS(st) == 1\n\
             try:\n    os.kill(agent, 9)\n    killed = 'ok'\n\
             except OSError as e:\n    killed = 'errno=' + errno.errorcode.get(e.errno, str(e.errno))\n\
             print(os.getpid(), refused, killed, flush=True)",
        )
        .arg(agent.to_string())
        .stdin(Stdio::null())
        .process_group(0)
        .output()
        .expect("run the actor");
    let said = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let f: Vec<&str> = said.split_whitespace().collect();
    assert_eq!(
        f.len(),
        3,
        "the actor said {said:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        f[1], "80",
        "a renice of the agent was not refused: {said:?}"
    );
    assert_eq!(
        f[2], "errno=EPERM",
        "kill -9 of the agent (pid {agent}) was not refused"
    );
    let alive = matches!(
        fx.enforce_run
            .as_mut()
            .expect("enforce run")
            .child
            .try_wait(),
        Ok(None)
    );
    assert!(alive, "the agent is gone after the refused kill");
    let actor: u32 = f[0].parse().expect("the actor's pid");
    assert_decisive_record_after_flood(&mut fx, &log, actor, "signal", "task_denial_rate");
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

    // 3. The authorised stop. Drop then removes the pins in its window.
    let mut run = fx.take_for_stop().expect("the sigio run");
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
