//! R14a — the compromised-worker harness (plan §3.1, §3.5; the brief's
//! "worker compromesso"; `docs/architecture/PROCESS_MODEL.md` §5).
//!
//! A worker whose parser an input took over is `--hostile <attack>`
//! (`nn_linux::worker::hostile`, lab builds only): started by the core's
//! own spawn path — this build's agent binary from a descriptor, as the
//! `northnarrow-worker` account, `no_new_privs`, its channel on 3 — it
//! enters the real sandbox and then attacks instead of parsing:
//!
//! 1. every forbidden system call — read the agent's key and a protected
//!    file, create a file, connect out (TCP, UDP, a UNIX socket by path —
//!    the D-Bus system bus where there is one —, an abstract socket),
//!    signal the core or init by every call that signals (`kill`,
//!    `tgkill`, `tkill`, `rt_sigqueueinfo`, a pidfd) and trace it,
//!    execute, fork, `bpf`, `setuid`, executable memory (`mmap`,
//!    `mprotect`, `pkey_mprotect`), a user namespace, `io_uring_setup`,
//!    `keyctl`, `perf_event_open`, `userfaultfd` — is killed by the seccomp
//!    filter (`SIGSYS`) on every kernel (review of #480, F5 and F7);
//! 2. beneath the filter (`noseccomp+`, this harness only), each layer
//!    refuses what the running kernel lets it: the account (DAC),
//!    `RLIMIT_NPROC`, the empty capability sets, Landlock at the kernel's
//!    ABI (files from 1, TCP from 4, signals and abstract sockets from 6).
//!    What no layer below the filter refuses on this kernel is asserted as
//!    such and printed: the declared level, never an assumed one. What a
//!    distribution's settings decide (user namespaces, `io_uring`,
//!    `perf_event_paranoid`, `userfaultfd`, …) is printed, not asserted;
//! 3. every protocol attack after a genuine hello — a malformed packet, an
//!    oversized one, an unknown id, a second hello, a flood, a lie in a
//!    result, a hello below its sandbox — is refused by the core's
//!    supervisor, which kills the worker; a descriptor sent along needs
//!    `sendmsg`, which the filter refuses (F8: the worker dies by
//!    `SIGSYS`); a worker that answers every ping and spins between them
//!    is killed as a hang (F12). The core (this test process) survives,
//!    and a new worker serves after them. A worker is started from the
//!    supervisor's thread only (its death signal is that thread's): the
//!    tests that start them through the supervisor run on a thread of
//!    that name.
//!
//! Run (lab guest, as root — `nn-lab.sh test-ignored` does):
//!   sudo -E env "PATH=$PATH" cargo test --release -p northnarrow-agent \
//!     --features "test-privileged debug-trigger" \
//!     --test privileged_worker_harness -- --ignored --test-threads=1

#![cfg(all(feature = "test-privileged", feature = "debug-trigger"))]

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nn_linux::worker::hostile::{DENIED, FAILED, SUCCEEDED};
use nn_linux::worker::spawn::spawn;
use nn_linux::worker::supervisor::{Config, ImageLauncher, NoPidRoles, SUPERVISOR_THREAD};
use nn_linux::worker::{Health, SelfImage, WorkerAccount, WorkerError, Workers, WORKER_USER};
use nn_proto::ipc::{QnameIn, Request, WorkerKind};

mod common;
use common::agent_state::{ensure_worker_account, InstalledAgent};

/// The installed agent's signing key, when this host has one: read by
/// the attack, never written.
const AGENT_KEY: &str = "/etc/northnarrow/agent.sig.key";

struct Harness {
    agent: InstalledAgent,
    account: WorkerAccount,
    dir: PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn harness() -> Harness {
    common::require_root("start workers as northnarrow-worker");
    ensure_worker_account();
    let agent = InstalledAgent::install();
    let account = WorkerAccount::lookup(WORKER_USER).expect("the worker account");
    // a directory every account may traverse, owned by root
    let dir = PathBuf::from(format!("/tmp/nn-worker-harness-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    Harness {
        agent,
        account,
        dir,
    }
}

impl Harness {
    fn image(&self) -> SelfImage {
        SelfImage::open(self.agent.agent_exe()).expect("open the agent's image")
    }

    /// One hostile worker with `attack`; its exit status (10 s at most).
    fn attack(&self, attack: &str) -> ExitStatus {
        let mut sp = spawn(
            &self.image(),
            WorkerKind::Parse,
            &self.account,
            &["--hostile".to_string(), attack.to_string()],
        )
        .expect("spawn a hostile worker");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(st) = sp.child.try_wait().unwrap() {
                return st;
            }
            assert!(Instant::now() < deadline, "{attack}: still running");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn file(&self, name: &str, mode: u32) -> PathBuf {
        let p = self.dir.join(name);
        std::fs::write(&p, b"secret").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }
}

fn sigsys(st: ExitStatus) -> bool {
    st.signal() == Some(libc::SIGSYS)
}

/// The D-Bus system bus, a UNIX socket by path every account may connect
/// to (where the guest runs one).
const DBUS: &str = "/run/dbus/system_bus_socket";

/// Run `f` on a thread named as the supervisor's: [`ImageLauncher`]
/// starts a worker from that thread only, since a worker's death signal
/// (`PR_SET_PDEATHSIG`) is the forking thread's.
fn as_supervisor(f: impl FnOnce() + Send + 'static) {
    let t = std::thread::Builder::new()
        .name(SUPERVISOR_THREAD.to_string())
        .spawn(f)
        .unwrap();
    if let Err(p) = t.join() {
        std::panic::resume_unwind(p);
    }
}

/// The listeners the connects aim at (accepting nothing): TCP and UDP on
/// loopback, an abstract UNIX socket, a UNIX socket by path any account
/// may connect to.
struct Listeners {
    tcp: std::net::TcpListener,
    udp: std::net::UdpSocket,
    _abstract: std::os::unix::net::UnixListener,
    name: String,
    _path: std::os::unix::net::UnixListener,
    path: PathBuf,
}

fn listeners(h: &Harness) -> Listeners {
    use std::os::linux::net::SocketAddrExt;
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    // a name of its own each call (a test may hold two sets at once)
    let n = N.fetch_add(1, Ordering::SeqCst);
    let name = format!("nn-worker-harness-{}-{n}", std::process::id());
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    let abs = std::os::unix::net::UnixListener::bind_addr(&addr).unwrap();
    let path = h.dir.join(format!("unix-{n}.sock"));
    let by_path = std::os::unix::net::UnixListener::bind(&path).unwrap();
    // writable by every account: DAC lets the worker connect
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    Listeners {
        tcp,
        udp,
        _abstract: abs,
        name,
        _path: by_path,
        path,
    }
}

/// Every system-call attack, with its argument.
fn syscall_attacks(h: &Harness, l: &Listeners) -> Vec<(String, &'static str)> {
    let port = l.tcp.local_addr().unwrap().port();
    let udp = l.udp.local_addr().unwrap().port();
    let name = &l.name;
    let secret = h.file("root-only", 0o600);
    let readable = h.file("world-readable", 0o644);
    let me = std::process::id();
    let mut v = vec![
        (format!("read:{}", secret.display()), "a root-only file"),
        (
            format!("read:{}", readable.display()),
            "a world-readable file",
        ),
        (format!("write:{}/created", h.dir.display()), "a new file"),
        (
            format!("write:/tmp/nn-worker-harness-{me}.out"),
            "a file in /tmp",
        ),
        (format!("connect:127.0.0.1:{port}"), "a TCP connect"),
        (format!("connect-abstract:{name}"), "an abstract socket"),
        (format!("kill:{me}"), "a signal to the core"),
        (format!("ptrace:{me}"), "a trace of the core"),
        ("exec".to_string(), "an exec"),
        ("fork".to_string(), "a fork"),
        ("bpf".to_string(), "a bpf call"),
        ("setuid".to_string(), "setuid(0)"),
        ("mmap-exec".to_string(), "executable memory"),
        // review of #480 (F5): what the review's mutations RM1 and RM2 let
        // through, unseen by the harness then
        (
            "mprotect-exec".to_string(),
            "a writable mapping made executable",
        ),
        ("pkey-mprotect".to_string(), "pkey_mprotect to executable"),
        (format!("tgkill:{me}"), "tgkill to the core"),
        ("tgkill:1".to_string(), "tgkill to init"),
        (format!("tkill:{me}"), "tkill to the core"),
        (
            format!("rt-sigqueueinfo:{me}"),
            "rt_sigqueueinfo to the core",
        ),
        (format!("pidfd-signal:{me}"), "a pidfd signal to the core"),
        // review of #480 (F7): what only the filter refuses everywhere
        (
            format!("connect-unix:{}", l.path.display()),
            "a UNIX socket by path",
        ),
        (format!("udp:127.0.0.1:{udp}"), "a UDP datagram"),
        ("unshare-userns".to_string(), "a user namespace"),
        ("io-uring".to_string(), "io_uring_setup"),
        ("keyctl".to_string(), "keyctl"),
        ("perf-event-open".to_string(), "perf_event_open"),
        ("userfaultfd".to_string(), "userfaultfd"),
    ];
    if Path::new(DBUS).exists() {
        v.push((format!("connect-unix:{DBUS}"), "the D-Bus system bus"));
    }
    if Path::new(AGENT_KEY).exists() {
        v.push((format!("read:{AGENT_KEY}"), "the agent's signing key"));
    }
    v
}

#[test]
#[ignore = "root, a lab guest: starts workers as northnarrow-worker"]
fn every_forbidden_call_is_killed_by_the_seccomp_filter() {
    let h = harness();
    // the listeners live while the attacks run
    let l = listeners(&h);
    for (attack, what) in syscall_attacks(&h, &l) {
        let st = h.attack(&attack);
        assert!(sigsys(st), "{what} ({attack}): {st:?}, not SIGSYS");
    }
    assert!(!h.dir.join("created").exists());
    assert!(!Path::new(&format!(
        "/tmp/nn-worker-harness-{}.out",
        std::process::id()
    ))
    .exists());
}

#[test]
#[ignore = "root, a lab guest: starts workers as northnarrow-worker"]
fn beneath_the_filter_each_layer_refuses_what_the_kernel_lets_it() {
    let h = harness();
    let abi = nn_linux::sandbox::kernel_landlock_abi();
    let l = listeners(&h);
    let port = l.tcp.local_addr().unwrap().port();
    let udp = l.udp.local_addr().unwrap().port();
    let name = l.name.clone();
    let secret = h.file("root-only", 0o600);
    let readable = h.file("world-readable", 0o644);
    let me = std::process::id();
    let tmp_out = format!("/tmp/nn-worker-harness-{me}.out");
    // (attack, what, the layer that refuses it, refused on this kernel —
    // `None`: the distribution decides, printed and not asserted)
    let mut cases: Vec<(String, &str, &str, Option<bool>)> = vec![
        (
            format!("read:{}", secret.display()),
            "a root-only file",
            "DAC + Landlock",
            Some(true),
        ),
        (
            format!("read:{}", readable.display()),
            "a world-readable file",
            "Landlock (ABI ≥ 1)",
            Some(abi >= 1),
        ),
        (
            format!("write:{}/created", h.dir.display()),
            "a file in a root directory",
            "DAC + Landlock",
            Some(true),
        ),
        (
            format!("write:{tmp_out}"),
            "a file in /tmp",
            "Landlock (ABI ≥ 1)",
            Some(abi >= 1),
        ),
        (
            format!("connect:127.0.0.1:{port}"),
            "a TCP connect",
            "Landlock (ABI ≥ 4)",
            Some(abi >= 4),
        ),
        (
            format!("connect-abstract:{name}"),
            "an abstract socket",
            "Landlock scope (ABI ≥ 6)",
            Some(abi >= 6),
        ),
        (
            format!("kill:{me}"),
            "SIGCONT to the core, same session",
            "Landlock scope (ABI ≥ 6)",
            Some(abi >= 6),
        ),
        (
            format!("ptrace:{me}"),
            "a trace of the core",
            "DAC (another uid, no CAP_SYS_PTRACE)",
            Some(true),
        ),
        (
            "exec".into(),
            "an exec of /bin/sh",
            "Landlock (ABI ≥ 1)",
            Some(abi >= 1),
        ),
        ("fork".into(), "a fork", "RLIMIT_NPROC 0", Some(true)),
        ("bpf".into(), "a bpf call", "no capability", Some(true)),
        ("setuid".into(), "setuid(0)", "no capability", Some(true)),
        (
            "mmap-exec".into(),
            "executable memory",
            "nothing below the filter",
            Some(false),
        ),
        // review of #480 (F5, F7)
        (
            "mprotect-exec".into(),
            "a writable mapping made executable",
            "nothing below the filter",
            Some(false),
        ),
        (
            "pkey-mprotect".into(),
            "pkey_mprotect to executable",
            "nothing below the filter",
            Some(false),
        ),
        (
            format!("tgkill:{me}"),
            "tgkill SIGCONT to the core",
            "Landlock scope (ABI ≥ 6)",
            Some(abi >= 6),
        ),
        (
            "tgkill:1".into(),
            "tgkill SIGCONT to init (another session)",
            "DAC (another uid)",
            Some(true),
        ),
        (
            format!("tkill:{me}"),
            "tkill SIGCONT to the core",
            "Landlock scope (ABI ≥ 6)",
            Some(abi >= 6),
        ),
        (
            format!("rt-sigqueueinfo:{me}"),
            "rt_sigqueueinfo SIGCONT to the core",
            "Landlock scope (ABI ≥ 6)",
            Some(abi >= 6),
        ),
        (
            format!("pidfd-signal:{me}"),
            "a pidfd SIGCONT to the core",
            "Landlock scope (ABI ≥ 6)",
            Some(abi >= 6),
        ),
        (
            format!("connect-unix:{}", l.path.display()),
            "a UNIX socket by path (mode 0666)",
            "no Landlock right on the lab's ABIs",
            None,
        ),
        (
            format!("udp:127.0.0.1:{udp}"),
            "a UDP datagram",
            "no Landlock right on the lab's ABIs",
            None,
        ),
        (
            "unshare-userns".into(),
            "a user namespace",
            "the distribution's userns policy",
            None,
        ),
        (
            "io-uring".into(),
            "io_uring_setup",
            "kernel.io_uring_disabled",
            None,
        ),
        ("keyctl".into(), "keyctl", "nothing below the filter", None),
        (
            "perf-event-open".into(),
            "perf_event_open",
            "kernel.perf_event_paranoid",
            None,
        ),
        (
            "userfaultfd".into(),
            "userfaultfd",
            "vm.unprivileged_userfaultfd",
            None,
        ),
    ];
    if Path::new(DBUS).exists() {
        cases.push((
            format!("connect-unix:{DBUS}"),
            "the D-Bus system bus",
            "no Landlock right on the lab's ABIs",
            None,
        ));
    }
    if Path::new(AGENT_KEY).exists() {
        cases.push((
            format!("read:{AGENT_KEY}"),
            "the agent's signing key",
            "DAC + Landlock (+ the BPF LSM when the agent runs)",
            Some(true),
        ));
    }
    let mut table = Vec::new();
    for (attack, what, layer, refused) in cases {
        let st = h.attack(&format!("noseccomp+{attack}"));
        let code = st.code();
        let verdict = match code {
            Some(DENIED) => "refused",
            Some(SUCCEEDED) => "went through",
            Some(FAILED) => "failed (another errno)",
            _ => "ended otherwise",
        };
        table.push(format!("{what}: {verdict} {code:?} ({layer})"));
        match refused {
            Some(true) => assert_eq!(
                code,
                Some(DENIED),
                "{what}: refused by {layer} on ABI {abi}: {st:?}"
            ),
            Some(false) => assert!(
                code == Some(SUCCEEDED) || code == Some(FAILED),
                "{what}: no layer below the filter on ABI {abi}: {st:?}"
            ),
            // printed: the declared level, never an assumed one
            None => assert!(
                matches!(code, Some(DENIED | SUCCEEDED | FAILED)),
                "{what}: the attack itself must end by its verdict: {st:?}"
            ),
        }
    }
    // what got through is removed; what was refused left nothing
    assert!(!h.dir.join("created").exists());
    let _ = std::fs::remove_file(&tmp_out);
    drop(l);
    println!("landlock ABI {abi}:\n  {}", table.join("\n  "));
}

fn names() -> Request {
    Request::DnsNames(vec![QnameIn {
        bytes: b"\x07example\x03com\x00".to_vec(),
        form: nn_proto::ipc::QnameForm::Wire,
    }])
}

/// A name whose end is asked for (the socket-buffer sensor's).
fn names_find_end() -> Request {
    Request::DnsNames(vec![QnameIn {
        bytes: b"\x07example\x03com\x00\x00\x01".to_vec(),
        form: nn_proto::ipc::QnameForm::WireFindEnd,
    }])
}

/// The signed reports a supervisor made (source, detail).
type Reports = Arc<parking_lot::Mutex<Vec<(String, String)>>>;

fn workers(h: &Harness, extra: &[&str]) -> Workers {
    workers_reporting(h, extra, Reports::default())
}

fn workers_reporting(h: &Harness, extra: &[&str], reports: Reports) -> Workers {
    Workers::new(Config {
        launcher: Arc::new(ImageLauncher {
            image: Some(h.image()),
            account: Ok(h.account.clone()),
            extra_args: extra.iter().map(|s| s.to_string()).collect(),
        }),
        roles: Arc::new(NoPidRoles),
        report: Arc::new(move |s: &str, d: &str| {
            eprintln!("degradation {s}: {d}");
            reports.lock().push((s.to_string(), d.to_string()));
        }),
        kinds: vec![WorkerKind::Parse],
        debug_dir: None,
    })
}

fn tick_until(w: &Workers, done: impl Fn(&Workers) -> bool) -> bool {
    tick_within(w, Duration::from_secs(10), done)
}

fn tick_within(w: &Workers, within: Duration, done: impl Fn(&Workers) -> bool) -> bool {
    let end = Instant::now() + within;
    while Instant::now() < end {
        w.tick(Instant::now());
        if done(w) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

#[test]
#[ignore = "root, a lab guest: starts workers as northnarrow-worker"]
fn every_protocol_attack_is_refused_and_the_core_survives() {
    as_supervisor(protocol_attacks);
}

fn protocol_attacks() {
    let h = harness();
    for attack in [
        "malformed",
        "oversized",
        "fd-pass",
        "unknown-id",
        "second-hello",
        "flood",
        "lie",
        // review of #481 (R14b-1)
        "refuse-all",
        "empty-names",
        "end-off-root",
    ] {
        let w = workers(&h, &["--hostile", attack]);
        assert!(
            tick_until(&w, |w| w.status()[0].health == Health::Ready),
            "{attack}: the hostile worker's genuine hello"
        );
        let req = if attack == "end-off-root" {
            names_find_end()
        } else {
            names()
        };
        let got = w.request(WorkerKind::Parse, &req, Duration::from_secs(2));
        // the flood answers the request first, then keeps sending: the
        // supervisor's next look finds the answers nobody asked for
        if attack != "flood" {
            assert!(
                matches!(got, Err(WorkerError::Violation(_) | WorkerError::Died(_))),
                "{attack}: {got:?}"
            );
        }
        // the flood's extra answers, if the request's own read took a good one
        tick_until(&w, |w| w.status()[0].deaths >= 1);
        let st = &w.status()[0];
        if attack == "fd-pass" {
            // F8: `sendmsg` is not the worker's any more — the filter ends
            // it before a descriptor leaves (the core's own refusal of one
            // is `transport`'s unit test)
            assert!(st.last_exit.contains("SIGSYS"), "{attack}: {st:?}");
        } else {
            assert!(st.violations >= 1, "{attack}: {st:?}");
        }
        assert_eq!(st.deaths, 1, "{attack}: killed once: {st:?}");
        w.stop();
    }
    // review of #481 (R14b-2): an answer past the names' deadline is a
    // hang — the worker killed — never a pass slowed in silence
    let w = workers(&h, &["--hostile", "slow"]);
    assert!(tick_until(&w, |w| w.status()[0].health == Health::Ready));
    let got = w.request(
        WorkerKind::Parse,
        &names(),
        nn_linux::worker::parse::NAMES_TIMEOUT,
    );
    assert!(got.is_err(), "slow: {got:?}");
    tick_until(&w, |w| w.status()[0].deaths >= 1);
    let st = w.status()[0].clone();
    assert!(st.hangs >= 1 && st.deaths == 1, "slow: {st:?}");
    w.stop();
    // a false but well-formed name: within every bound the core checks —
    // printed, not asserted (Open: the round-trip check of a name against
    // its bytes)
    let w = workers(&h, &["--hostile", "swap"]);
    assert!(tick_until(&w, |w| w.status()[0].health == Health::Ready));
    let got = w.request(WorkerKind::Parse, &names(), Duration::from_secs(2));
    println!(
        "swap (a false, well-formed name): {got:?}; {:?}",
        w.status()[0]
    );
    w.stop();
    // a hello below its sandbox never makes the worker ready
    let w = workers(&h, &["--hostile", "weak-hello"]);
    assert!(tick_until(&w, |w| w.status()[0].violations >= 1));
    assert_ne!(w.status()[0].health, Health::Ready);
    w.stop();
    // the core is alive (this process) and a worker serves after them
    let w = workers(&h, &[]);
    assert!(tick_until(&w, |w| w.status()[0].health == Health::Ready));
    match w.request(WorkerKind::Parse, &names(), Duration::from_secs(2)) {
        Ok(nn_proto::ipc::Answer::DnsNames(n)) => assert_eq!(n[0].name, "example.com"),
        other => panic!("{other:?}"),
    }
    w.stop();
}

#[test]
#[ignore = "root, a lab guest: starts workers as northnarrow-worker"]
fn a_worker_that_spins_between_pings_is_killed_as_a_hang() {
    // review of #480 (F12): every ping answered in time, the CPU burnt
    // between them — the supervisor's spin check, not the ping, ends it
    as_supervisor(|| {
        let h = harness();
        let reports = Reports::default();
        let w = workers_reporting(&h, &["--hostile", "spin"], reports.clone());
        assert!(tick_until(&w, |w| w.status()[0].health == Health::Ready));
        assert!(
            tick_within(&w, Duration::from_secs(30), |w| w.status()[0].hangs >= 1),
            "{:?}",
            w.status()[0]
        );
        let st = w.status()[0].clone();
        w.stop();
        let seen = reports.lock().clone();
        println!("spin: {st:?}\n  reports: {seen:?}");
        assert!(
            seen.iter().any(|(_, d)| d.contains("spinning")),
            "the spin is the reason, signed: {seen:?}"
        );
    });
}

#[test]
#[ignore = "root, a lab guest: starts workers as northnarrow-worker"]
fn a_worker_is_started_from_the_supervisor_s_thread_only() {
    // PR_SET_PDEATHSIG is the forking thread's: from any other thread the
    // launch is refused, and the refusal is reported
    let h = harness();
    let reports = Reports::default();
    let w = workers_reporting(&h, &[], reports.clone());
    w.tick(Instant::now());
    let st = w.status()[0].clone();
    w.stop();
    assert_eq!(st.pid, None, "{st:?}");
    let seen = reports.lock().clone();
    assert!(
        seen.iter().any(|(_, d)| d.contains(SUPERVISOR_THREAD)),
        "{seen:?}"
    );
}

#[test]
#[ignore = "root, a lab guest: starts workers as northnarrow-worker"]
fn an_honest_worker_declares_the_sandbox_this_kernel_gives() {
    as_supervisor(honest_worker);
}

fn honest_worker() {
    let h = harness();
    let w = workers(&h, &[]);
    assert!(tick_until(&w, |w| w.status()[0].health == Health::Ready));
    let st = w.status()[0].clone();
    w.stop();
    let l = st.sandbox.expect("a sandbox level");
    let abi = nn_linux::sandbox::kernel_landlock_abi();
    println!(
        "kernel landlock ABI {abi}; the worker declared: {}",
        l.summary()
    );
    assert_eq!((l.uid, l.gid, l.groups), (h.account.uid, h.account.gid, 0));
    assert!(l.seccomp && l.no_new_privs && !l.dumpable);
    assert_eq!((l.cap_eff, l.cap_prm, l.cap_inh, l.cap_amb), (0, 0, 0, 0));
    assert_eq!((l.nproc, l.core), (0, 0));
    assert_eq!(l.landlock_abi, abi.min(9));
    assert_eq!(l.fs_denied, abi >= 1);
    assert_eq!(l.net_denied, abi >= 4);
    assert_eq!(l.scoped, abi >= 6);
    // the worker's own view of its process: no core, no files beyond its
    // channel — read from outside, while one runs
    let w = workers(&h, &[]);
    assert!(tick_until(&w, |w| w.status()[0].health == Health::Ready));
    let pid = w.status()[0].pid.unwrap();
    let mut status = String::new();
    std::fs::File::open(format!("/proc/{pid}/status"))
        .unwrap()
        .read_to_string(&mut status)
        .unwrap();
    let field = |k: &str| {
        status
            .lines()
            .find(|l| l.starts_with(k))
            .map(|l| l[k.len()..].trim().to_string())
            .unwrap_or_default()
    };
    assert_eq!(field("NoNewPrivs:"), "1");
    assert_eq!(field("Seccomp:"), "2");
    assert_eq!(field("CapEff:"), "0000000000000000");
    // review of #480 (F12): the first the OOM killer takes, the last the
    // scheduler serves
    let oom = std::fs::read_to_string(format!("/proc/{pid}/oom_score_adj")).unwrap();
    assert_eq!(oom.trim(), "1000");
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let after_comm = stat.rsplit_once(')').unwrap().1;
    // fields after the comm: state is 3, nice is 19
    let nice: i32 = after_comm
        .split_whitespace()
        .nth(19 - 3)
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(nice, 10);
    // (F4, its stderr a pipe the core reads, is the supervisor's unit
    // test: the kernel refuses this root process the worker's descriptor
    // links — `EACCES` on the lab's Ubuntu 22.04, round ra2204)
    let fds: Vec<_> = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(fds.len() <= 4, "stdio and the channel only: {fds:?}");
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap();
    assert_eq!(comm.trim(), "nn-worker-parse");
    w.stop();
}
