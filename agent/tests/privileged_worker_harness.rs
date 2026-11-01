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
//!    file, create a file, connect out, connect to an abstract socket,
//!    signal and trace the core, execute, fork, `bpf`, `setuid`,
//!    executable memory — is killed by the seccomp filter (`SIGSYS`);
//! 2. beneath the filter (`noseccomp+`, this harness only), each layer
//!    refuses what the running kernel lets it: the account (DAC),
//!    `RLIMIT_NPROC`, the empty capability sets, Landlock at the kernel's
//!    ABI (files from 1, TCP from 4, signals and abstract sockets from 6).
//!    What no layer below the filter refuses on this kernel is asserted as
//!    such and printed: the declared level, never an assumed one;
//! 3. every protocol attack after a genuine hello — a malformed packet, an
//!    oversized one, a descriptor, an unknown id, a second hello, a flood,
//!    a lie in a result, a hello below its sandbox — is refused by the
//!    core's supervisor, which kills the worker; the core (this test
//!    process) survives, and a new worker serves after it.
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
use nn_linux::worker::supervisor::{Config, ImageLauncher, NoPidRoles};
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

/// A TCP listener on loopback and an abstract UNIX listener, for the
/// connects (accepting nothing).
fn listeners() -> (
    std::net::TcpListener,
    std::os::unix::net::UnixListener,
    String,
) {
    use std::os::linux::net::SocketAddrExt;
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    // a name of its own each call (a test may hold two sets at once)
    let name = format!(
        "nn-worker-harness-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    );
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    let unix = std::os::unix::net::UnixListener::bind_addr(&addr).unwrap();
    (tcp, unix, name)
}

/// Every system-call attack, with its argument.
fn syscall_attacks(h: &Harness) -> Vec<(String, &'static str)> {
    let (tcp, _unix, name) = listeners();
    let port = tcp.local_addr().unwrap().port();
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
    ];
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
    let (_t, _u, _n) = listeners();
    for (attack, what) in syscall_attacks(&h) {
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
    let (tcp, unix, name) = listeners();
    let port = tcp.local_addr().unwrap().port();
    let secret = h.file("root-only", 0o600);
    let readable = h.file("world-readable", 0o644);
    let me = std::process::id();
    let tmp_out = format!("/tmp/nn-worker-harness-{me}.out");
    // (attack, what, the layer that refuses it or None, refused on this kernel)
    let mut cases: Vec<(String, &str, &str, bool)> = vec![
        (
            format!("read:{}", secret.display()),
            "a root-only file",
            "DAC + Landlock",
            true,
        ),
        (
            format!("read:{}", readable.display()),
            "a world-readable file",
            "Landlock (ABI ≥ 1)",
            abi >= 1,
        ),
        (
            format!("write:{}/created", h.dir.display()),
            "a file in a root directory",
            "DAC + Landlock",
            true,
        ),
        (
            format!("write:{tmp_out}"),
            "a file in /tmp",
            "Landlock (ABI ≥ 1)",
            abi >= 1,
        ),
        (
            format!("connect:127.0.0.1:{port}"),
            "a TCP connect",
            "Landlock (ABI ≥ 4)",
            abi >= 4,
        ),
        (
            format!("connect-abstract:{name}"),
            "an abstract socket",
            "Landlock scope (ABI ≥ 6)",
            abi >= 6,
        ),
        (
            format!("kill:{me}"),
            "SIGCONT to the core, same session",
            "Landlock scope (ABI ≥ 6)",
            abi >= 6,
        ),
        (
            format!("ptrace:{me}"),
            "a trace of the core",
            "DAC (another uid, no CAP_SYS_PTRACE)",
            true,
        ),
        (
            "exec".into(),
            "an exec of /bin/sh",
            "Landlock (ABI ≥ 1)",
            abi >= 1,
        ),
        ("fork".into(), "a fork", "RLIMIT_NPROC 0", true),
        ("bpf".into(), "a bpf call", "no capability", true),
        ("setuid".into(), "setuid(0)", "no capability", true),
        (
            "mmap-exec".into(),
            "executable memory",
            "nothing below the filter",
            false,
        ),
    ];
    if Path::new(AGENT_KEY).exists() {
        cases.push((
            format!("read:{AGENT_KEY}"),
            "the agent's signing key",
            "DAC + Landlock (+ the BPF LSM when the agent runs)",
            true,
        ));
    }
    let mut table = Vec::new();
    for (attack, what, layer, refused) in cases {
        let st = h.attack(&format!("noseccomp+{attack}"));
        let code = st.code();
        table.push(format!("{what}: {code:?} ({layer})"));
        if refused {
            assert_eq!(
                code,
                Some(DENIED),
                "{what}: refused by {layer} on ABI {abi}: {st:?}"
            );
        } else {
            assert!(
                code == Some(SUCCEEDED) || code == Some(FAILED),
                "{what}: no layer below the filter on ABI {abi}: {st:?}"
            );
        }
    }
    // what got through is removed; what was refused left nothing
    assert!(!h.dir.join("created").exists());
    let _ = std::fs::remove_file(&tmp_out);
    drop((tcp, unix));
    println!("landlock ABI {abi}:\n  {}", table.join("\n  "));
}

fn names() -> Request {
    Request::DnsNames(vec![QnameIn {
        bytes: b"\x07example\x03com\x00".to_vec(),
        find_end: false,
    }])
}

fn workers(h: &Harness, extra: &[&str]) -> Workers {
    Workers::new(Config {
        launcher: Arc::new(ImageLauncher {
            image: Some(h.image()),
            account: Ok(h.account.clone()),
            extra_args: extra.iter().map(|s| s.to_string()).collect(),
        }),
        roles: Arc::new(NoPidRoles),
        report: Arc::new(|s: &str, d: &str| eprintln!("degradation {s}: {d}")),
        kinds: vec![WorkerKind::Parse],
        debug_dir: None,
    })
}

fn tick_until(w: &Workers, done: impl Fn(&Workers) -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(10);
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
    let h = harness();
    for attack in [
        "malformed",
        "oversized",
        "fd-pass",
        "unknown-id",
        "second-hello",
        "flood",
        "lie",
    ] {
        let w = workers(&h, &["--hostile", attack]);
        assert!(
            tick_until(&w, |w| w.status()[0].health == Health::Ready),
            "{attack}: the hostile worker's genuine hello"
        );
        let got = w.request(WorkerKind::Parse, &names(), Duration::from_secs(2));
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
        assert!(st.violations >= 1, "{attack}: {st:?}");
        assert_eq!(st.deaths, 1, "{attack}: killed once: {st:?}");
        w.stop();
    }
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
fn an_honest_worker_declares_the_sandbox_this_kernel_gives() {
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
