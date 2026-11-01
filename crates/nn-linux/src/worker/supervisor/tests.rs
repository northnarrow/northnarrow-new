//! The supervisor against scripted workers: a real child process (`sleep`,
//! which the supervisor kills and reaps) and a thread on the worker's end
//! of the channel that speaks the protocol honestly or not.

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::process::Command;
use std::sync::atomic::AtomicU32;

use nn_proto::ipc::{
    LandlockEnforced, QnameIn, QnameOut, Response, ToWorker, WorkerHello, IPC_VERSION,
};

use super::*;
use crate::worker::serve;

const UID: u32 = 4242;
const GID: u32 = 4243;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Script {
    Honest,
    NoHello,
    WeakHello,
    WrongPid,
    MalformedAnswer,
    WrongId,
    WrongKind,
    SecondHello,
    Unsolicited,
    Oversized,
    Descriptor,
    Hang,
    DieOnRequest,
    BadCharset,
    TooManyNames,
}

fn level() -> SandboxLevel {
    SandboxLevel {
        landlock_abi: 4,
        landlock: LandlockEnforced::Full,
        fs_denied: true,
        net_denied: true,
        seccomp: true,
        no_new_privs: true,
        uid: UID,
        gid: GID,
        nofile: 8,
        ..SandboxLevel::default()
    }
}

fn send(fd: RawFd, m: &FromWorker) {
    let _ = transport::send(fd, &encode(m).unwrap());
}

fn raw_send(fd: RawFd, bytes: &[u8]) {
    let iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    // SAFETY: zeroed msghdr with one live iovec.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    // SAFETY: sendmsg on our socket.
    unsafe { libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL) };
}

fn send_with_fd(fd: RawFd, pass: RawFd) {
    let payload = encode(&FromWorker::Response(Response {
        id: 1,
        answer: Answer::Pong,
    }))
    .unwrap();
    let iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let mut cbuf = [0u64; 8];
    // SAFETY: zeroed msghdr, a control buffer for one descriptor.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    // SAFETY: CMSG_* within cbuf.
    unsafe {
        msg.msg_controllen = libc::CMSG_SPACE(4) as _;
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(4) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(c) as *mut RawFd, pass);
        libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL);
    }
}

fn run_script(script: Script, sock: OwnedFd, pid: u32) {
    let fd = sock.as_raw_fd();
    let mut hello = WorkerHello {
        version: IPC_VERSION,
        kind: WorkerKind::Parse,
        pid,
        sandbox: level(),
    };
    match script {
        Script::NoHello => {
            std::thread::sleep(Duration::from_secs(30));
            return;
        }
        Script::WeakHello => hello.sandbox.seccomp = false,
        Script::WrongPid => hello.pid = pid + 1,
        _ => {}
    }
    send(fd, &FromWorker::Hello(hello.clone()));
    let mut buf = vec![0u8; MAX_FRAME];
    loop {
        let n = match transport::recv(fd, &mut buf, false) {
            Ok(Recv::Packet(n)) => n,
            _ => return,
        };
        let msg: ToWorker = decode(&buf[..n]).unwrap();
        let honest = serve::answer(&msg.req);
        let reply = |answer| FromWorker::Response(Response { id: msg.id, answer });
        match script {
            Script::MalformedAnswer => raw_send(fd, &[0xff, 0xff, 0xff]),
            Script::WrongId => send(
                fd,
                &FromWorker::Response(Response {
                    id: msg.id + 7,
                    answer: honest,
                }),
            ),
            Script::WrongKind => send(fd, &reply(Answer::Pong)),
            Script::SecondHello => send(fd, &FromWorker::Hello(hello.clone())),
            Script::Unsolicited => {
                send(fd, &reply(honest.clone()));
                send(fd, &reply(honest));
            }
            Script::Oversized => raw_send(fd, &vec![0u8; MAX_FRAME + 1]),
            Script::Descriptor => send_with_fd(fd, fd),
            Script::Hang => {}
            Script::DieOnRequest => return,
            Script::BadCharset => match &msg.req {
                Request::DnsNames(n) => send(
                    fd,
                    &reply(Answer::DnsNames(
                        n.iter()
                            .map(|_| QnameOut {
                                name: "evil\ninjected".into(),
                                end: None,
                            })
                            .collect(),
                    )),
                ),
                _ => send(fd, &reply(honest)),
            },
            Script::TooManyNames => match &msg.req {
                Request::DnsNames(n) => send(
                    fd,
                    &reply(Answer::DnsNames(vec![
                        QnameOut {
                            name: "a".into(),
                            end: None
                        };
                        n.len() + 1
                    ])),
                ),
                _ => send(fd, &reply(honest)),
            },
            _ => send(fd, &reply(honest)),
        }
    }
}

struct Scripted {
    script: Script,
    launches: AtomicU32,
}

impl Launcher for Scripted {
    fn unavailable(&self) -> Option<String> {
        None
    }
    fn account(&self) -> Option<(u32, u32)> {
        Some((UID, GID))
    }
    fn launch(&self, _kind: WorkerKind) -> std::io::Result<Spawned> {
        self.launches.fetch_add(1, Ordering::SeqCst);
        // stdio closed: a child left by a failing test holds no pipe of
        // the harness's (the fixture stops it on drop)
        let child = Command::new("sleep")
            .arg("600")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let (ours, theirs) = transport::socketpair()?;
        let pid = child.id();
        let script = self.script;
        std::thread::spawn(move || run_script(script, theirs, pid));
        Ok(Spawned { child, sock: ours })
    }
}

#[derive(Default)]
struct Recorder {
    registered: Mutex<Vec<u32>>,
    evicted: Mutex<Vec<u32>>,
}

impl PidRoles for Recorder {
    fn register_worker(&self, pid: u32) -> Result<(), String> {
        self.registered.lock().push(pid);
        Ok(())
    }
    fn evict(&self, pid: u32) -> Result<(), String> {
        self.evicted.lock().push(pid);
        Ok(())
    }
}

struct Fixture {
    workers: Workers,
    roles: Arc<Recorder>,
    reports: Arc<Mutex<Vec<(String, String)>>>,
    launcher: Arc<Scripted>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.workers.stop();
    }
}

fn fixture(script: Script) -> Fixture {
    let roles = Arc::new(Recorder::default());
    let reports: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    let r = Arc::clone(&reports);
    let launcher = Arc::new(Scripted {
        script,
        launches: AtomicU32::new(0),
    });
    let workers = Workers::new(Config {
        launcher: launcher.clone(),
        roles: roles.clone(),
        report: Arc::new(move |src: &str, d: &str| r.lock().push((src.into(), d.into()))),
        kinds: vec![WorkerKind::Parse],
        debug_dir: None,
    });
    Fixture {
        workers,
        roles,
        reports,
        launcher,
    }
}

fn health(w: &Workers) -> Health {
    w.status()[0].health
}

/// Tick until `kind`'s health is `want` (5 s at most).
fn tick_until(w: &Workers, want: Health) -> bool {
    let end = Instant::now() + Duration::from_secs(8);
    while Instant::now() < end {
        w.tick(Instant::now());
        if health(w) == want {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

fn names() -> Request {
    Request::DnsNames(vec![QnameIn {
        bytes: b"\x07example\x03com\x00".to_vec(),
        find_end: false,
    }])
}

#[test]
fn an_honest_worker_serves_and_its_pid_is_registered_then_evicted() {
    let f = fixture(Script::Honest);
    assert!(tick_until(&f.workers, Health::Ready));
    let pid = f.workers.status()[0].pid.unwrap();
    assert_eq!(*f.roles.registered.lock(), vec![pid]);
    match f
        .workers
        .request(WorkerKind::Parse, &names(), Duration::from_secs(2))
    {
        Ok(Answer::DnsNames(n)) => assert_eq!(n[0].name, "example.com"),
        other => panic!("{other:?}"),
    }
    let st = &f.workers.status()[0];
    assert_eq!((st.starts, st.deaths, st.violations), (1, 0, 0));
    assert_eq!(st.sandbox.as_ref().map(|l| l.landlock_abi), Some(4));
    f.workers.stop();
    assert_eq!(*f.roles.evicted.lock(), vec![pid]);
    assert_eq!(health(&f.workers), Health::Stopped);
    assert_eq!(
        f.workers
            .request(WorkerKind::Parse, &Request::Ping, Duration::from_millis(50)),
        Err(WorkerError::Unavailable(Health::Stopped))
    );
    assert!(f.reports.lock().is_empty());
}

#[test]
fn no_request_reaches_a_worker_that_is_not_ready() {
    let f = fixture(Script::NoHello);
    f.workers.tick(Instant::now());
    assert_eq!(health(&f.workers), Health::Starting);
    assert_eq!(
        f.workers
            .request(WorkerKind::Parse, &names(), Duration::from_millis(50)),
        Err(WorkerError::Unavailable(Health::Starting))
    );
    // its hello is late: killed, reaped, evicted, reported
    f.workers.tick(Instant::now() + READY_TIMEOUT);
    let st = &f.workers.status()[0];
    assert_eq!(st.deaths, 1);
    assert!(st.last_exit.contains("SIGKILL"), "{}", st.last_exit);
    assert_eq!(f.roles.evicted.lock().len(), 1);
    assert!(f.reports.lock()[0].1.contains("no hello within"));
    assert_eq!(f.reports.lock()[0].0, "worker_parse");
}

#[test]
fn a_hello_below_its_sandbox_or_from_another_pid_is_refused() {
    for script in [Script::WeakHello, Script::WrongPid] {
        let f = fixture(script);
        let end = Instant::now() + Duration::from_secs(5);
        while f.workers.status()[0].violations == 0 && Instant::now() < end {
            f.workers.tick(Instant::now());
            std::thread::sleep(Duration::from_millis(5));
        }
        let st = &f.workers.status()[0];
        assert_eq!(st.violations, 1, "{script:?}");
        assert_ne!(st.health, Health::Ready, "{script:?}");
        let r = f.reports.lock();
        assert!(r[0].1.contains("hello refused"), "{script:?}: {r:?}");
    }
}

#[test]
fn every_protocol_violation_kills_the_worker_and_is_reported() {
    for (script, req, expect) in [
        (Script::MalformedAnswer, names(), "malformed packet"),
        (Script::WrongId, names(), "not the oldest"),
        (Script::WrongKind, names(), "wrong kind"),
        (Script::SecondHello, names(), "a second hello"),
        (Script::Oversized, names(), "above 65536"),
        (Script::Descriptor, Request::Ping, "carried a descriptor"),
        (Script::BadCharset, names(), "name characters"),
        (Script::TooManyNames, names(), "one answer per name"),
    ] {
        let f = fixture(script);
        assert!(tick_until(&f.workers, Health::Ready), "{script:?}");
        let pid = f.workers.status()[0].pid.unwrap();
        let got = f
            .workers
            .request(WorkerKind::Parse, &req, Duration::from_secs(2));
        assert!(
            matches!(&got, Err(WorkerError::Violation(v)) if v.contains(expect)),
            "{script:?}: {got:?}"
        );
        let st = &f.workers.status()[0];
        assert_eq!((st.violations, st.deaths), (1, 1), "{script:?}");
        assert_ne!(st.health, Health::Ready);
        assert_eq!(*f.roles.evicted.lock(), vec![pid], "{script:?}");
        assert!(
            f.reports.lock().iter().any(|(_, d)| d.contains(expect)),
            "{script:?}: {:?}",
            f.reports.lock()
        );
    }
}

#[test]
fn a_flood_of_answers_nobody_asked_for_is_caught() {
    let f = fixture(Script::Unsolicited);
    assert!(tick_until(&f.workers, Health::Ready));
    // the first answer is good; the second is waiting
    assert!(f
        .workers
        .request(WorkerKind::Parse, &names(), Duration::from_secs(2))
        .is_ok());
    std::thread::sleep(Duration::from_millis(50));
    f.workers.tick(Instant::now());
    let st = &f.workers.status()[0];
    assert_eq!(st.violations, 1);
    assert!(f
        .reports
        .lock()
        .iter()
        .any(|(_, d)| d.contains("no request asked for")));
}

/// The flood's extra answer is found by the next request too, before it is
/// sent (no tick in between): a packet nobody asked for is never read as an
/// answer.
#[test]
fn a_left_answer_is_caught_by_the_next_request() {
    let f = fixture(Script::Unsolicited);
    assert!(tick_until(&f.workers, Health::Ready));
    assert!(f
        .workers
        .request(WorkerKind::Parse, &names(), Duration::from_secs(2))
        .is_ok());
    std::thread::sleep(Duration::from_millis(50));
    let got = f
        .workers
        .request(WorkerKind::Parse, &names(), Duration::from_secs(2));
    assert!(
        matches!(&got, Err(WorkerError::Violation(v)) if v.contains("no request asked for")),
        "{got:?}"
    );
    assert_eq!(f.workers.status()[0].violations, 1);
}

#[test]
fn a_hung_worker_is_killed_at_its_deadline() {
    let f = fixture(Script::Hang);
    assert!(tick_until(&f.workers, Health::Ready));
    let t = Instant::now();
    assert_eq!(
        f.workers
            .request(WorkerKind::Parse, &names(), Duration::from_millis(200)),
        Err(WorkerError::Timeout)
    );
    assert!(t.elapsed() < Duration::from_secs(2));
    let st = &f.workers.status()[0];
    assert_eq!((st.hangs, st.deaths), (1, 1));
    // an idle hung worker is found by the ping
    let f = fixture(Script::Hang);
    assert!(tick_until(&f.workers, Health::Ready));
    f.workers.tick(Instant::now() + PING_EVERY);
    assert_eq!(f.workers.status()[0].hangs, 1);
}

#[test]
fn a_worker_that_dies_with_a_request_is_reaped() {
    let f = fixture(Script::DieOnRequest);
    assert!(tick_until(&f.workers, Health::Ready));
    let got = f
        .workers
        .request(WorkerKind::Parse, &names(), Duration::from_secs(2));
    assert!(matches!(got, Err(WorkerError::Died(_))), "{got:?}");
    assert_eq!(f.workers.status()[0].deaths, 1);
}

#[test]
fn failures_in_a_row_back_off_then_disable_then_a_stable_worker_enables() {
    let f = fixture(Script::DieOnRequest);
    let mut t = Instant::now();
    for i in 1..=DISABLE_AFTER {
        assert!(
            tick_until(&f.workers, Health::Ready) || i == DISABLE_AFTER,
            "start {i}"
        );
        let _ = f
            .workers
            .request(WorkerKind::Parse, &names(), Duration::from_secs(2));
        let st = &f.workers.status()[0];
        assert_eq!(st.failures, i);
        if i < DISABLE_AFTER {
            assert_ne!(st.health, Health::Disabled);
            // the backoff holds the next start
            t = Instant::now();
            if backoff(i) > Duration::ZERO {
                f.workers.tick(t);
                assert_eq!(f.workers.status()[0].health, Health::Backoff, "{i}");
            }
            f.workers.tick(t + backoff(i));
        }
    }
    let st = &f.workers.status()[0];
    assert_eq!(st.health, Health::Disabled);
    assert!(st.why.contains("failures in a row"));
    assert!(f
        .reports
        .lock()
        .iter()
        .any(|(_, d)| d.starts_with("disabled:")));
    // disabled: refused at once, whatever runs
    f.workers.tick(Instant::now() + MAX_BACKOFF);
    assert!(matches!(
        f.workers
            .request(WorkerKind::Parse, &Request::Ping, Duration::from_millis(50)),
        Err(WorkerError::Unavailable(Health::Disabled))
    ));
    let _ = t;
}

#[test]
fn a_stable_worker_clears_its_failures_and_enables_its_kind() {
    let f = fixture(Script::Honest);
    assert!(tick_until(&f.workers, Health::Ready));
    {
        let slot = f.workers.slot(WorkerKind::Parse).unwrap();
        let mut s = slot.s.lock();
        s.failures = DISABLE_AFTER;
        s.disabled = true;
        s.why = "test".into();
    }
    assert_eq!(health(&f.workers), Health::Disabled);
    f.workers.tick(Instant::now() + STABLE);
    let st = &f.workers.status()[0];
    assert_eq!((st.health, st.failures), (Health::Ready, 0));
    assert!(st.why.is_empty());
}

#[test]
fn reports_are_folded_within_a_minute_but_violations_go_at_once() {
    let f = fixture(Script::DieOnRequest);
    for _ in 0..3 {
        assert!(tick_until(&f.workers, Health::Ready));
        let _ = f
            .workers
            .request(WorkerKind::Parse, &names(), Duration::from_secs(2));
        f.workers.tick(Instant::now() + MAX_BACKOFF);
    }
    // three deaths, one report (the others folded into the next)
    assert_eq!(f.reports.lock().len(), 1, "{:?}", f.reports.lock());
    assert!(f.launcher.launches.load(Ordering::SeqCst) >= 3);
}

#[test]
fn the_backoff_grows_to_its_cap() {
    assert_eq!(backoff(1), Duration::ZERO);
    assert_eq!(backoff(2), Duration::from_secs(1));
    assert_eq!(backoff(3), Duration::from_secs(2));
    assert_eq!(backoff(6), Duration::from_secs(16));
    assert_eq!(backoff(8), MAX_BACKOFF);
    assert_eq!(backoff(40), MAX_BACKOFF);
}

#[test]
fn exits_are_named() {
    use std::os::unix::process::ExitStatusExt;
    let st = |raw| std::process::ExitStatus::from_raw(raw);
    assert!(describe_exit(st(libc::SIGSYS)).contains("seccomp"));
    assert!(describe_exit(st(EXIT_SANDBOX << 8)).contains("sandbox"));
    assert!(describe_exit(st(0)).contains("channel closed"));
}

#[test]
fn an_unavailable_launcher_is_reported_once_and_never_started() {
    let roles = Arc::new(Recorder::default());
    let reports: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    let r = Arc::clone(&reports);
    let w = Workers::new(Config {
        launcher: Arc::new(ImageLauncher {
            image: None,
            account: Err("no user".into()),
            extra_args: vec![],
        }),
        roles,
        report: Arc::new(move |s: &str, d: &str| r.lock().push((s.into(), d.into()))),
        kinds: vec![WorkerKind::Parse],
        debug_dir: None,
    });
    w.tick(Instant::now());
    let st = &w.status()[0];
    w.stop();
    assert_eq!((st.health, st.starts), (Health::Unavailable, 0));
    assert_eq!(reports.lock().len(), 1);
    assert!(reports.lock()[0].1.starts_with("cannot start"));
}
