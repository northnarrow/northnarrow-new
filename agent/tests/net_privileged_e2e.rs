//! Tappa 10 N9 — privileged end-to-end tests for the Network
//! Observability subsystem (CLOSES TAPPA 10).
//!
//! Spawns the real `northnarrow-agent` binary against a per-test
//! tempdir, drives a kernel-side observation (TCP connect + close,
//! TCP listen() bind), then asserts the resulting row in the
//! chained `netflow.jsonl` / `netflow_listeners.jsonl`. Verifies
//! end-to-end on a real kernel that:
//!
//! - the three N2 BPF programs attach via
//!   [`SensorMultiplexer::start_with_net`] (`inet_csk_listen_start`
//!   kprobe + `tcp_close` fexit + `udp_sendmsg_outbound` kprobe);
//! - the drain loop reads `NET_FLOW_CLOSE_EVENTS` +
//!   `NET_LISTEN_EVENTS`, threads each record through
//!   `FlowTracker` / `DnsCache`, and persists to the on-disk
//!   chain;
//! - the N6 rule layer fires NN-L-NET-006 on the uncommon-port
//!   listener test: its signed record is asserted in the per-test
//!   `--detections-file` (external audit NN-AUD-229).
//!
//! Three §11.2 priv-e2e were originally listed; test #2
//! (JA3 fingerprint) is DEFERRED to Tappa 11.5 per §13 Q2 packet-
//! capture atomicity lock-in. The N5 TLS parser is unit-tested
//! via 12 fixtures (Chrome 120, Firefox 120, curl 8, Cobalt Strike
//! default JA3, …); activation gates on the
//! `tcp_data_capture_trigger` BPF program landing alongside the
//! user-space pcap writer in one atomic Tappa 11.5 commit. See
//! `docs/design/TAPPA10_NETWORK_OBSERVABILITY_DESIGN.md` §11.2 +
//! §13 Q2.
//!
//! Requirements (operator-runnable per
//! `docs/integration-test-runbook.md`):
//! - root (or CAP_SYS_ADMIN + CAP_NET_ADMIN + CAP_BPF);
//! - kernel with `bpf` in `/sys/kernel/security/lsm` + fexit
//!   support (5.5+; production target 6.8.x);
//! - `/sys/fs/bpf` mounted as bpffs;
//! - workspace built `--release --features test-privileged`;
//! - working `python3` (test #1 spawns a one-shot helper that
//!   does a TCP `connect` + `close`).
//!
//! Run:
//!   sudo -E env "PATH=$PATH" cargo test --release \
//!     -p northnarrow-agent --test net_privileged_e2e \
//!     --features "test-privileged debug-trigger" \
//!     -- --include-ignored --test-threads=1

#![cfg(feature = "test-privileged")]

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::{install_to_priv_bin, EniIptablesGuard, InstalledBin};

const SOCKET_POLL_TIMEOUT: Duration = Duration::from_secs(15);
const JSONL_POLL_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Test process's TCP destination port. Picked high enough to
/// avoid privileged-port conflicts but stable across boots so a
/// single rule (NN-L-NET-006 uncommon-port listener) can be
/// pinned in tests. NOT port 22 — `localhost:22` (§11.2 example)
/// would tangle the test with the host's SSH daemon which may
/// or may not be running.
const FLOW_DST_PORT: u16 = 33999;

/// FQDN the DNS-attribution test resolves. `.invalid` (RFC 2606)
/// guarantees NXDOMAIN — the query hits the wire (what the kprobe +
/// PID-keyed DnsCache need) but never resolves to a real host, so no
/// egress leaves the isolated target.
const DNS_ATTRIBUTION_HOST: &str = "foo.northnarrow-e2etest.invalid";

/// Uncommon listener port for test #2. Outside the §7
/// allowlist `{22, 53, 80, 443, 8080, 8443}` so NN-L-NET-006
/// fires; not 12345 (per §11.2 example) because we want a
/// random ephemeral-range port to avoid collisions with other
/// services running on a developer's VM.
const LISTENER_PORT: u16 = 41999;
/// Test #2's negative twin: a port in the NN-L-NET-006 allowlist.
const ALLOWLISTED_PORT: u16 = 8443;
const NET_006: &str = "NN-L-NET-006_UncommonListener";
/// Test #3 — destination port of the unconnected UDP `sendto()`
/// burst. Nothing listens there; the datagrams are dropped locally
/// and ICMP-unreachable is irrelevant for the kprobe.
const UDP_SENDTO_PORT: u16 = 34999;
/// Review 68: the IPv6 datagram's destination port, and the port of the
/// IPv4-mapped one sent from the same IPv6 socket. Nothing listens.
const UDP6_SENDTO_PORT: u16 = 35997;
const UDP6_MAPPED_PORT: u16 = 35998;
/// Review 73: the connected-UDP burst's destination, and the TCP listener
/// the same helper connects to during the burst.
const UDP_BURST_PORT: u16 = 35996;
const TCP_DURING_BURST_PORT: u16 = 35995;

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

// ── R009 avoidance + RAII fixtures (same shape as canary_priv) ───────

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

/// Per-test agent fixture. Spawns the agent with a tempdir layout
/// and the netflow blocklists wired to empty files (so NN-L-NET-001
/// and NN-L-NET-003 don't accidentally match anything during the
/// e2e). Drop order matters: AgentGuard before InstalledBin so the
/// agent stops before its binary is removed.
struct NetFixture {
    _tempdir: tempfile::TempDir,
    netflow_log: PathBuf,
    netflow_listeners_log: PathBuf,
    admin_priv: PathBuf,
    agent_id_file: PathBuf,
    admin_socket: PathBuf,
    nn_admin_path: PathBuf,
    /// Per-test detection chain (`--detections-file`).
    detections_log: PathBuf,
    _agent_guard: AgentGuard,
    _installed_agent: InstalledBin,
    _installed_admin: InstalledBin,
}

impl NetFixture {
    fn setup() -> Self {
        wipe_pin_tree();
        let tempdir = tempfile::tempdir().expect("tempdir");
        let dir = tempdir.path().to_path_buf();

        let (installed_agent, installed_admin) = install_priv_bins();

        // Per-test admin keypair — same shape as canary fixture.
        let admin_pub = dir.join("admin.pub");
        let admin_priv = dir.join("admin.priv");
        let tmp_pub = dir.join("admin.pub.tmp");
        let init_status = Command::new(&installed_admin.path)
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

        // FIM paths config: empty list — we don't trigger any FIM
        // events from these net tests.
        let fim_paths_v1 = dir.join("fim-paths.v1");
        std::fs::write(&fim_paths_v1, "").expect("write fim-paths.v1");
        let fim_paths_local = dir.join("fim-paths.local");
        std::fs::write(&fim_paths_local, "").expect("write fim-paths.local");

        // Canary template dir — copy the workspace defaults so
        // the canary-template-dir flag points at something real,
        // even though no canary is deployed in these tests.
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

        // N9 netflow blocklists — empty so NN-L-NET-001 / 003
        // never match incidentally during the e2e.
        let netflow_blocklist_v1 = dir.join("netflow-blocklist.v1");
        std::fs::write(&netflow_blocklist_v1, "").expect("write netflow-blocklist.v1");
        let netflow_blocklist_local = dir.join("netflow-blocklist.local");
        std::fs::write(&netflow_blocklist_local, "").expect("write netflow-blocklist.local");
        let netflow_ja3_blocklist_v1 = dir.join("netflow-ja3-blocklist.v1");
        std::fs::write(&netflow_ja3_blocklist_v1, "").expect("write netflow-ja3-blocklist.v1");
        let netflow_ja3_blocklist_local = dir.join("netflow-ja3-blocklist.local");
        std::fs::write(&netflow_ja3_blocklist_local, "")
            .expect("write netflow-ja3-blocklist.local");

        let audit_log = dir.join("audit.log");
        let signing_key = dir.join("agent.sig.key");
        let agent_id = dir.join("agent_id");
        let admin_socket = dir.join("admin.sock");
        let marker = dir.join("agent.shutdown_authorised");
        let baseline_log = dir.join("fim_baseline.jsonl");
        let drift_log = dir.join("fim_drift.jsonl");
        let canary_registry = dir.join("canaries.jsonl");
        let canary_access = dir.join("canary_access.jsonl");
        let netflow_log = dir.join("netflow.jsonl");
        let netflow_listeners_log = dir.join("netflow_listeners.jsonl");
        let detections_log = dir.join("detections.jsonl");

        common::require_bpftool();
        let child = Command::new("sudo")
            .arg("env")
            .arg(common::OWN_DEFAULT_LISTS_ASSIGNMENT)
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
            .arg("--detections-file")
            .arg(&detections_log)
            .arg("--status-events-file")
            .arg(dir.join("status_events.jsonl"))
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
            .arg("--netflow-file")
            .arg(&netflow_log)
            .arg("--netflow-listeners-file")
            .arg(&netflow_listeners_log)
            .arg("--netflow-blocklist-v1")
            .arg(&netflow_blocklist_v1)
            .arg("--netflow-blocklist-local")
            .arg(&netflow_blocklist_local)
            .arg("--netflow-ja3-blocklist-v1")
            .arg(&netflow_ja3_blocklist_v1)
            .arg("--netflow-ja3-blocklist-local")
            .arg(&netflow_ja3_blocklist_local)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn northnarrow-agent for net e2e");
        let guard = AgentGuard(Some(child));

        wait_for_socket(&admin_socket);

        Self {
            _tempdir: tempdir,
            netflow_log,
            netflow_listeners_log,
            admin_priv,
            agent_id_file: agent_id,
            admin_socket,
            nn_admin_path: installed_admin.path.clone(),
            detections_log,
            _agent_guard: guard,
            _installed_agent: installed_agent,
            _installed_admin: installed_admin,
        }
    }

    /// Block until `netflow.jsonl` holds at least `n` rows matching
    /// `predicate`; return them. Polls at POLL_INTERVAL up to
    /// JSONL_POLL_TIMEOUT.
    fn wait_netflow_matching<F>(&self, n: usize, predicate: F) -> Vec<serde_json::Value>
    where
        F: Fn(&serde_json::Value) -> bool,
    {
        wait_jsonl_matching(&self.netflow_log, n, predicate)
    }

    fn wait_listeners_matching<F>(&self, n: usize, predicate: F) -> Vec<serde_json::Value>
    where
        F: Fn(&serde_json::Value) -> bool,
    {
        wait_jsonl_matching(&self.netflow_listeners_log, n, predicate)
    }

    /// `nn-admin net <args>` against this agent with the fixture's key
    /// (role `all`); the JSONL rows it printed.
    fn nn_admin_net(&self, args: &[&str]) -> Vec<serde_json::Value> {
        let sub = args.join(" ");
        let out = Command::new(&self.nn_admin_path)
            .arg("net")
            .args(args)
            .arg("--key")
            .arg(&self.admin_priv)
            .arg("--agent-id-file")
            .arg(&self.agent_id_file)
            .arg("--socket")
            .arg(&self.admin_socket)
            .stderr(Stdio::inherit())
            .output()
            .expect("spawn nn-admin net");
        assert!(
            out.status.success(),
            "nn-admin net {sub}: exit {:?}",
            out.status
        );
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("nn-admin net row is JSON"))
            .collect()
    }
}

fn install_priv_bins() -> (InstalledBin, InstalledBin) {
    let installed_agent = install_to_priv_bin(Path::new(agent_bin()));
    let installed_admin = install_to_priv_bin(Path::new(nn_admin_bin()));
    (installed_agent, installed_admin)
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

fn wait_jsonl_matching<F>(path: &Path, n: usize, predicate: F) -> Vec<serde_json::Value>
where
    F: Fn(&serde_json::Value) -> bool,
{
    let deadline = Instant::now() + JSONL_POLL_TIMEOUT;
    while Instant::now() < deadline {
        let rows = common::read_jsonl_strict(path);
        let matched: Vec<_> = rows.iter().filter(|r| predicate(r)).cloned().collect();
        if matched.len() >= n {
            return matched;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    let rows = common::read_jsonl_strict(path);
    panic!(
        "log {} held {} matching rows after {:?} — wanted >= {}; \
         all rows: {:?}",
        path.display(),
        rows.iter().filter(|r| predicate(r)).count(),
        JSONL_POLL_TIMEOUT,
        n,
        rows
    );
}

// ── Test 1: outbound TCP flow to a loopback destination ─────────────

/// N9 e2e #1 — outbound TCP flow correlation for a loopback dst.
/// Spawn the agent, open a TcpListener on `127.0.0.1:<FLOW_DST_PORT>`
/// to accept the test's TCP connection, then run a one-shot
/// python3 helper that opens + closes a TCP socket to that port.
/// The agent's N9 drain loop MUST correlate the kernel-side
/// `tcp_v4_connect` kprobe (Tappa 4) with the `tcp_close` fexit
/// (Tappa 10 N2) and write a chained row to `netflow.jsonl` with
/// the expected 5-tuple + signed chain primitives.
///
/// **Why this is the loopback-correlation test specifically:**
/// pre-N9.1, the Tappa 4 `tcp_v[46]_connect` kprobe skipped
/// 127.0.0.0/8 dsts (commit 210c596, May 2026), which was a
/// defensible outbound-monitoring filter at the time but broke
/// Tappa 10's flow-correlation contract end-to-end (no
/// FLOW_SOCK_MAP write → tcp_close lookup miss → drain drops the
/// close as an orphan → zero `netflow.jsonl` rows). N9.1 removes
/// the skip; this test pins the END-TO-END kernel→userland wire
/// on a loopback five-tuple so the regression can't sneak back in
/// (operator-visibility gap re container-to-container loopback
/// C2 in shared-netns Kubernetes pods).
///
/// **§11.2 DNS-attribution coverage — restored by the Tappa 4.1 DNS
/// observability refit.** The original §11.2 spec asserted
/// `resolved_hostname` is populated via `DnsCache::lookup_for_connect`;
/// that assertion was DEFERRED in the N9.1 hotfix because the Tappa 4
/// `dns_query` kprobe had two pre-existing bugs the N9 priv-e2e was the
/// first to expose end-to-end. T4.1 closed both:
///   - Bug 2 — the kprobe early-returned when `msghdr->msg_name ==
///     NULL`, which is exactly the connected-UDP shape libc resolvers
///     emit (`connect()` + `send()`). The kprobe now falls back to the
///     socket's `__sk_common` destination, so it fires for real
///     resolution.
///   - Bug 3 — the kernel side never copied the QNAME. It now walks
///     `msg_iter` (ITER_UBUF) and copies the label-encoded QNAME, so
///     userland decodes the real name.
///
/// With both fixed, the PID-keyed `DnsCache` records the helper's
/// query and `lookup_for_connect` attributes it to the immediately
/// following connect from the same PID → `resolved_hostname`.
///
/// **Lab PR 229 — deterministic.** The query, the connect and the close
/// come on three rings read by three tasks; a close read before the DNS
/// pump had read the helper's query left `resolved_hostname` null (the
/// Ubuntu 24.04 flake, CI run 39602279581). The drain now waits for a pass
/// of the DNS pump begun after the close (`DnsIngest`), so the query is in
/// the cache whenever the lookup runs. Where `nsswitch.conf` puts `resolve`
/// before `dns` (Debian 13) the helper sends no datagram: systemd-resolved
/// is asked over varlink, and the name comes from the uprobe on its NSS
/// module (`agent-ebpf/src/dns_nss.rs`) — the same assertion holds there.
///
/// The helper queries an FQDN (trailing dot) so glibc skips
/// `resolv.conf` search-domain expansion and the most-recent observed
/// QNAME is deterministically the literal we assert.
///
/// **§11.2 test #2 (JA3 fingerprint)** stays DEFERRED to
/// Tappa 11.5 per §13 Q2 packet-capture atomicity lock-in
/// (separate, pre-existing deferral — unchanged here).
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn net_outbound_connect_records_flow_with_dns_attribution() {
    let _eni = EniIptablesGuard::install();
    let fx = NetFixture::setup();

    // Pre-bind the destination on the host so the TCP connect
    // succeeds → tcp_close fexit fires with graceful close
    // (close_reason = 0). Without a listener, the connect would
    // ECONNREFUSED + the close path differs; we want the cleanest
    // observation of a real flow. The listener accepts one
    // connection then is dropped at end-of-test.
    let listener = TcpListener::bind(("127.0.0.1", FLOW_DST_PORT))
        .expect("bind 127.0.0.1:<FLOW_DST_PORT> for test #1 receiver");
    let accept_thread = std::thread::spawn(move || {
        // Accept one connection + close immediately. The peer
        // (python subprocess) holds the socket open just long
        // enough to populate the kernel's `tcp_sock` byte
        // counters before the close().
        if let Ok((stream, _)) = listener.accept() {
            drop(stream);
        }
    });

    // Spawn the helper. python3 is universally present on the
    // production target; if it's missing, we want a clear failure
    // message rather than a silent skip. The helper resolves an FQDN
    // (the kprobe captures the connected-UDP DNS query, or the NSS uprobe
    // the name asked of systemd-resolved → PID-keyed DnsCache), then
    // connects to loopback from the SAME PID so the
    // drain loop attributes the qname to the flow. The `.invalid`
    // TLD guarantees NXDOMAIN (no real egress); the query still goes
    // on the wire, which is all the attribution needs. The trailing
    // dot makes it absolute → no search-domain expansion, so the
    // most-recent observed QNAME is exactly the asserted literal.
    let helper = format!(
        r#"
import socket
try:
    socket.gethostbyname("{host}.")
except Exception:
    pass
s = socket.socket()
s.settimeout(2)
try:
    s.connect(("127.0.0.1", {port}))
except Exception:
    pass
try:
    s.shutdown(socket.SHUT_RDWR)
except Exception:
    pass
s.close()
"#,
        host = DNS_ATTRIBUTION_HOST,
        port = FLOW_DST_PORT,
    );
    let status = Command::new("python3")
        .arg("-c")
        .arg(&helper)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .expect("spawn python3 helper for net flow test #1");
    assert!(
        status.success(),
        "python3 helper exited non-zero: {status:?}"
    );
    let _ = accept_thread.join();

    // Wait for the netflow row with our destination port. Other
    // background TCP activity on the host may also append rows
    // — we filter by dst_port to anchor on ours.
    let rows = fx.wait_netflow_matching(1, |r| {
        r["dst_port"].as_u64() == Some(FLOW_DST_PORT as u64)
            && r["dst_addr"].as_str() == Some("127.0.0.1")
    });
    let row = &rows[0];
    assert_eq!(row["proto"].as_u64(), Some(6), "proto must be TCP (6)");
    // Audit `net-src-1` (PR #164): the row carries the CLOSE-time
    // source, read by the tcp_close fexit after the kernel bound the
    // local end — not the connect-time wildcard the kprobe sees.
    assert_eq!(
        row["src_addr"].as_str(),
        Some("127.0.0.1"),
        "src_addr should be the close-time local address (loopback), \
         not the connect-time 0.0.0.0 wildcard; got {:?}",
        row["src_addr"]
    );
    assert!(
        row["src_port"].as_u64().is_some_and(|p| p > 0),
        "src_port should be the close-time ephemeral port; got {:?}",
        row["src_port"]
    );
    // The flow_id is the per-flow stable ID — 32 lowercase hex
    // chars of SHA-256(start_ns || five_tuple || pid)[..16].
    let flow_id = row["flow_id"].as_str().unwrap_or("");
    assert_eq!(
        flow_id.len(),
        32,
        "flow_id should be 32 hex chars (design §4.1); got {flow_id:?}"
    );
    assert!(
        flow_id.chars().all(|c| c.is_ascii_hexdigit()),
        "flow_id must be lowercase hex; got {flow_id:?}"
    );
    // Chain integrity smoke: signed row carries non-empty
    // prev_hash, entry_hash, agent_sig per design §4.4.
    assert_eq!(
        row["entry_hash"].as_str().unwrap_or("").len(),
        64,
        "entry_hash should be 64 hex chars (SHA-256)"
    );
    assert!(
        row["agent_sig"].as_str().is_some_and(|s| !s.is_empty()),
        "agent_sig must be present on a chained row"
    );
    // DNS attribution (restored by the T4.1 refit): the helper's
    // resolution of DNS_ATTRIBUTION_HOST is captured by the dns_query
    // kprobe and back-correlated to this same-PID connect.
    assert_eq!(
        row["resolved_hostname"].as_str(),
        Some(DNS_ATTRIBUTION_HOST),
        "resolved_hostname should be the helper's queried FQDN \
         (T4.1 DNS attribution); got {:?}",
        row["resolved_hostname"]
    );

    // External audit NN-AUD-080/081/082: the operator verbs serve this
    // row from `--netflow-file` (they read the built-in path), newest
    // first, and `net fingerprint` finds it by id (it answered empty).
    let flows = fx.nn_admin_net(&["flows"]);
    assert!(
        flows.iter().any(|r| r["flow_id"].as_str() == Some(flow_id)),
        "`nn-admin net flows` must list flow {flow_id}"
    );
    let fp = fx.nn_admin_net(&["fingerprint", "--flow-id", flow_id]);
    assert!(
        !fp.is_empty() && fp.iter().all(|r| r["flow_id"].as_str() == Some(flow_id)),
        "`nn-admin net fingerprint` must return the rows of flow {flow_id}: {fp:?}"
    );
}

// ── Test 2: uncommon-port listener trips NN-L-NET-006 ──────────────

/// N9 e2e #2 — listener observation + NN-L-NET-006 rule fire.
/// Open a TCP listener on `LISTENER_PORT` (outside the NN-L-NET-006
/// allowlist {22, 53, 80, 443, 8080, 8443}); the agent's
/// `inet_csk_listen_start` kprobe MUST fire, the drain loop
/// MUST append a row to `netflow_listeners.jsonl`, and the
/// matching NN-L-NET-006 rule MUST fire: its signed record (Medium,
/// Log, the test process as principal) is asserted in the detection
/// chain. External audit NN-AUD-229: the rule was never asserted — the
/// row alone stayed green with the rule removed. A listener on an
/// allowlisted port opened first must not fire it.
///
/// The rule's `Medium` severity → `posture→ALERTED` per N6, which
/// does NOT install the iptables `NORTHNARROW_COMBAT` chain
/// (that's reserved for Combat). EniIptablesGuard is still
/// instantiated for symmetry with test #1 + as a defence against
/// future rule-severity drift.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn net_listener_on_uncommon_port_records_event() {
    let _eni = EniIptablesGuard::install();
    let fx = NetFixture::setup();

    // Twin first: a listener on a common port (8443). Since lab PR 186 the
    // port alone exempts nothing — this test binary is outside the system
    // trees, so it is recorded too. The listener below comes later on the
    // same ring and is its barrier.
    // Skipped (said so) when the port is taken on this host.
    let allowlisted = match TcpListener::bind(("127.0.0.1", ALLOWLISTED_PORT)) {
        Ok(l) => {
            std::thread::sleep(Duration::from_millis(50));
            drop(l);
            true
        }
        Err(e) => {
            eprintln!("127.0.0.1:{ALLOWLISTED_PORT} not bindable ({e}): common-port twin skipped");
            false
        }
    };

    // Open + drop a TCP listener. The `inet_csk_listen_start`
    // kprobe fires on the kernel-side listen() call (binding
    // alone isn't enough — listen() is the transition the
    // probe hooks). `TcpListener::bind` performs both syscalls.
    {
        let _listener = TcpListener::bind(("127.0.0.1", LISTENER_PORT))
            .expect("bind 127.0.0.1:<LISTENER_PORT> for test #2");
        // Hold the listener open just long enough for the kernel
        // event to propagate through the ringbuf → drain →
        // append. 50 ms is comfortably above the drain task's
        // tokio cadence.
        std::thread::sleep(Duration::from_millis(50));
    }

    // Wait for the listeners-log row with our bind port. Other
    // background listeners on the host may also append rows;
    // filter by bind_port to anchor on ours.
    let rows =
        fx.wait_listeners_matching(1, |r| r["bind_port"].as_u64() == Some(LISTENER_PORT as u64));
    let row = &rows[0];
    assert_eq!(
        row["proto"].as_u64(),
        Some(6),
        "TCP listener proto must be 6 (IPPROTO_TCP)"
    );
    assert!(
        row["bind_addr"]
            .as_str()
            .is_some_and(|s| s == "127.0.0.1" || s == "0.0.0.0"),
        "bind_addr should be 127.0.0.1 (or 0.0.0.0 if kernel \
         wildcarded) — got {:?}",
        row["bind_addr"]
    );
    // Chain integrity smoke.
    assert_eq!(
        row["entry_hash"].as_str().unwrap_or("").len(),
        64,
        "entry_hash should be 64 hex chars (SHA-256)"
    );
    assert!(
        row["agent_sig"].as_str().is_some_and(|s| !s.is_empty()),
        "agent_sig must be present on a chained row"
    );

    // NN-L-NET-006 rule fire: the signed record of this listener. The
    // record names no port; the principal is this test process, which
    // opened it, and the listener row carries the same pid.
    let me = u64::from(std::process::id());
    assert_eq!(row["pid"].as_u64(), Some(me), "listener row: {row}");
    let rec = common::wait_jsonl_row(
        &fx.detections_log,
        JSONL_POLL_TIMEOUT,
        "NN-L-NET-006 record",
        |r| r["rule_id"] == NET_006 && r["principal"]["pid"].as_u64() == Some(me),
    );
    assert_eq!(rec["severity"], "Medium", "record: {rec}");
    assert_eq!(
        rec["verdict"],
        serde_json::json!({"Rule": "Log"}),
        "record: {rec}"
    );
    assert_eq!(rec["sensor"], "Network", "record: {rec}");
    assert_eq!(rec["response"], "none", "record: {rec}");
    if allowlisted {
        // Lab PR 186 (NETR-015): a common port alone no longer exempts a
        // listener; only a program installed in a root-owned system tree
        // does. This test binary is not one, so its 8443 listener is
        // recorded too (the record names no port; the verdict's reasoning
        // in the journal does).
        let records = common::records_of(&fx.detections_log, NET_006);
        let mine: Vec<_> = records
            .iter()
            .filter(|r| r["principal"]["pid"].as_u64() == Some(me))
            .collect();
        assert_eq!(
            mine.len(),
            2,
            "both listeners of this test binary fire NN-L-NET-006, the one on \
             {ALLOWLISTED_PORT} as a program outside the system trees: {records:?}"
        );
    }

    // External audit NN-AUD-081/082: the operator verb serves that row,
    // from the file `--netflow-listeners-file` names (it answered
    // Success with an empty body, and the flows verb read the built-in
    // path).
    let served = fx.nn_admin_net(&["listeners"]);
    assert!(
        served
            .iter()
            .any(|r| r["bind_port"].as_u64() == Some(LISTENER_PORT as u64)),
        "`nn-admin net listeners` must list port {LISTENER_PORT}: {served:?}"
    );
}

// ── Test 3: unconnected UDP sendto() records a flow row ─────────────

/// Review `net-udp-blind-1` — before the fix the
/// `udp_sendmsg_outbound` kprobe skipped every send whose socket had
/// no connected peer (`skc_dport == 0`), i.e. plain `sendto()`: a
/// QUIC-like beacon or raw-UDP exfil through an unconnected socket
/// produced no network event at all. The kprobe now resolves the
/// destination from `msghdr->msg_name` and rate-limits emissions to
/// one per `(pid, dst)` per second.
///
/// The helper sends a tight burst of 40 datagrams to a closed
/// loopback port from one unconnected socket. Expect: at least one
/// `netflow.jsonl` row with `proto = 17` and our destination, and
/// FAR fewer rows than datagrams (the kernel-side rate limit).
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn net_unconnected_udp_sendto_records_rate_limited_flow() {
    let _eni = EniIptablesGuard::install();
    let fx = NetFixture::setup();

    let helper = format!(
        r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(40):
    try:
        s.sendto(b"nn-udp-blind-1 " * 4, ("127.0.0.1", {port}))
    except Exception:
        pass
s.close()
"#,
        port = UDP_SENDTO_PORT,
    );
    let status = Command::new("python3")
        .arg("-c")
        .arg(&helper)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .expect("spawn python3 helper for net flow test #3");
    assert!(
        status.success(),
        "python3 helper exited non-zero: {status:?}"
    );

    let is_ours = |r: &serde_json::Value| {
        r["proto"].as_u64() == Some(17)
            && r["dst_port"].as_u64() == Some(UDP_SENDTO_PORT as u64)
            && r["dst_addr"].as_str() == Some("127.0.0.1")
    };
    let rows = fx.wait_netflow_matching(1, is_ours);
    let row = &rows[0];
    assert_eq!(row["proto"].as_u64(), Some(17), "proto must be UDP (17)");
    assert!(
        row["bytes_sent"].as_u64().is_some_and(|b| b > 0),
        "bytes_sent must carry the datagram length; got {:?}",
        row["bytes_sent"]
    );
    assert!(
        row["comm"]
            .as_str()
            .is_some_and(|c| c.starts_with("python")),
        "comm must be the python helper; got {:?}",
        row["comm"]
    );
    assert_eq!(
        row["entry_hash"].as_str().unwrap_or("").len(),
        64,
        "entry_hash should be 64 hex chars (SHA-256)"
    );

    // Rate limit: count once the drain has settled (external audit
    // NN-AUD-228: the same count over two windows, not a fixed sleep a
    // slower drain passes vacuously). The burst takes well under a
    // second, so the kernel-side limiter admits 1 row (2 if the burst
    // straddles a second boundary) — never one per datagram.
    let ours = common::wait_count_stable(Duration::from_secs(1), JSONL_POLL_TIMEOUT, || {
        common::read_jsonl_strict(&fx.netflow_log)
            .into_iter()
            .filter(is_ours)
            .count()
    });
    assert!(
        (1..=3).contains(&ours),
        "unconnected sendto burst of 40 must be rate-limited to ~1 row/s per (pid, dst); got {ours} rows"
    );
}

/// Review 68: the N2 UDP program was attached to `udp_sendmsg` only, so a
/// datagram to an IPv6 destination left no flow row. It is now attached to
/// `udpv6_sendmsg` too. An IPv4-mapped destination, which `udpv6_sendmsg`
/// hands to `udp_sendmsg`, must still give exactly one row.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn net_ipv6_udp_sendto_records_one_flow() {
    let _eni = EniIptablesGuard::install();
    let fx = NetFixture::setup();

    let helper = format!(
        r#"
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
for dst in (("::1", {p6}), ("::ffff:127.0.0.1", {pm})):
    try:
        s.sendto(b"nn-udp-v6 " * 4, dst)
    except Exception:
        pass
s.close()
"#,
        p6 = UDP6_SENDTO_PORT,
        pm = UDP6_MAPPED_PORT,
    );
    let status = Command::new("python3")
        .arg("-c")
        .arg(&helper)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .expect("spawn python3 helper for the IPv6 UDP flow test");
    assert!(
        status.success(),
        "python3 helper exited non-zero: {status:?}"
    );

    let v6 = |r: &serde_json::Value| {
        r["proto"].as_u64() == Some(17)
            && r["dst_port"].as_u64() == Some(UDP6_SENDTO_PORT as u64)
            && r["dst_addr"].as_str() == Some("::1")
    };
    let rows = fx.wait_netflow_matching(1, v6);
    assert!(
        rows[0]["comm"]
            .as_str()
            .is_some_and(|c| c.starts_with("python")),
        "comm must be the python helper; got {:?}",
        rows[0]["comm"]
    );

    let mapped = |r: &serde_json::Value| {
        r["proto"].as_u64() == Some(17) && r["dst_port"].as_u64() == Some(UDP6_MAPPED_PORT as u64)
    };
    fx.wait_netflow_matching(1, mapped);
    // Counted once settled (NN-AUD-228), not after a fixed sleep.
    let n = common::wait_count_stable(Duration::from_secs(1), JSONL_POLL_TIMEOUT, || {
        common::read_jsonl_strict(&fx.netflow_log)
            .into_iter()
            .filter(mapped)
            .count()
    });
    assert_eq!(
        n, 1,
        "an IPv4-mapped destination must give one row (udp_sendmsg), not one per hook"
    );
}

/// Review 73: a connected UDP socket emitted one record per `send()`, into
/// the ring the TCP closes share. An unprivileged burst lost 1.45 M records
/// in 10 s on the lab, the TCP flows of the moment with them. Sends are now
/// aggregated per destination in the kernel (one record per second, or per
/// MiB, carrying the bytes since the last), and UDP has its own ring.
#[test]
#[ignore = "requires sudo + bpf LSM (run via integration runbook)"]
fn net_connected_udp_burst_is_aggregated_and_spares_tcp_flows() {
    let _eni = EniIptablesGuard::install();
    let fx = NetFixture::setup();

    let listener = TcpListener::bind(("127.0.0.1", TCP_DURING_BURST_PORT))
        .expect("bind the TCP listener for the burst test");
    let accept_thread = std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            std::thread::sleep(Duration::from_millis(200));
            drop(stream);
        }
    });

    // 20,000 datagrams of 512 bytes (about 10 MB) on one connected socket,
    // and a TCP connection opened half-way through.
    let helper = format!(
        r#"
import socket
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.connect(("127.0.0.1", {udp}))
payload = b"b" * 512
for i in range(20000):
    try:
        u.send(payload)
    except OSError:
        pass
    if i == 10000:
        t = socket.create_connection(("127.0.0.1", {tcp}), timeout=2)
        t.sendall(b"nn-tcp-during-burst")
        t.close()
u.close()
"#,
        udp = UDP_BURST_PORT,
        tcp = TCP_DURING_BURST_PORT,
    );
    let status = Command::new("python3")
        .arg("-c")
        .arg(&helper)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .expect("spawn python3 helper for the UDP burst test");
    assert!(
        status.success(),
        "python3 helper exited non-zero: {status:?}"
    );
    let _ = accept_thread.join();

    let tcp_row = |r: &serde_json::Value| {
        r["proto"].as_u64() == Some(6)
            && r["dst_port"].as_u64() == Some(TCP_DURING_BURST_PORT as u64)
    };
    fx.wait_netflow_matching(1, tcp_row);

    let udp_row = |r: &serde_json::Value| {
        r["proto"].as_u64() == Some(17) && r["dst_port"].as_u64() == Some(UDP_BURST_PORT as u64)
    };
    fx.wait_netflow_matching(1, udp_row);
    // Read once the row count has settled (NN-AUD-228), not after a fixed
    // sleep.
    common::wait_count_stable(Duration::from_secs(1), JSONL_POLL_TIMEOUT, || {
        common::read_jsonl_strict(&fx.netflow_log)
            .into_iter()
            .filter(udp_row)
            .count()
    });
    let rows: Vec<serde_json::Value> = common::read_jsonl_strict(&fx.netflow_log)
        .into_iter()
        .filter(udp_row)
        .collect();
    let bytes: u64 = rows.iter().filter_map(|r| r["bytes_sent"].as_u64()).sum();
    assert!(
        (1..=60).contains(&rows.len()),
        "20,000 sends to one destination must be aggregated; got {} rows",
        rows.len()
    );
    // The last interval of each CPU (under 1 MiB) waits for a next send.
    assert!(
        bytes >= 5_000_000,
        "the aggregated rows must carry most of the ~10 MB sent; got {bytes} bytes in {} rows",
        rows.len()
    );
}
