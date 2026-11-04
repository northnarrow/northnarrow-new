//! The supervisor against scripted workers: a real child process (`sleep`,
//! which the supervisor kills and reaps) and a thread on the worker's end
//! of the channel that speaks the protocol honestly or not.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
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
    /// Review of #480 (F2): answers each ping on time (it watches its
    /// queue's length) but never reads a request.
    NoRead,
    /// Review of #481 (R14b-1): a refusal of every checked request; an
    /// empty name for a name's bytes; an end that is not just past the
    /// root label. (R14b-2): the names answered after 100 ms.
    RefuseAll,
    EmptyNames,
    EndOffRoot,
    SlowNames,
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
    if script == Script::NoRead {
        let mut id = 1u64;
        let mut seen = 0;
        loop {
            let mut q: libc::c_int = 0;
            // SAFETY: FIONREAD into a local int.
            if unsafe { libc::ioctl(fd, libc::FIONREAD, &mut q) } != 0 {
                return;
            }
            if q > seen {
                seen = q;
                send(
                    fd,
                    &FromWorker::Response(Response {
                        id,
                        answer: Answer::Pong,
                    }),
                );
                id += 1;
            } else {
                std::thread::sleep(Duration::from_micros(200));
            }
            // the core closed its end: this side's next send fails
            let mut pfd = libc::pollfd {
                fd,
                events: 0,
                revents: 0,
            };
            // SAFETY: one valid pollfd, no wait.
            unsafe { libc::poll(&mut pfd, 1, 0) };
            if pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                return;
            }
        }
    }
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
            Script::RefuseAll => match &msg.req {
                Request::Ping => send(fd, &reply(honest)),
                _ => send(
                    fd,
                    &reply(Answer::Refused(nn_proto::ipc::Refusal::OutOfBounds)),
                ),
            },
            Script::EmptyNames | Script::EndOffRoot => match &msg.req {
                Request::DnsNames(n) => send(
                    fd,
                    &reply(Answer::DnsNames(
                        n.iter()
                            .map(|_| QnameOut {
                                name: if script == Script::EmptyNames {
                                    String::new()
                                } else {
                                    "example.com".into()
                                },
                                end: (script == Script::EndOffRoot).then_some(2),
                            })
                            .collect(),
                    )),
                ),
                _ => send(fd, &reply(honest)),
            },
            Script::SlowNames => {
                if matches!(msg.req, Request::DnsNames(_)) {
                    std::thread::sleep(Duration::from_millis(100));
                }
                send(fd, &reply(honest));
            }
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
    fn kernel_landlock_abi(&self) -> u8 {
        level().landlock_abi
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
        Ok(Spawned {
            child,
            sock: ours,
            stderr: None,
        })
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
        form: nn_proto::ipc::QnameForm::Wire,
    }])
}

fn names_find_end() -> Request {
    Request::DnsNames(vec![QnameIn {
        bytes: b"\x07example\x03com\x00\x00\x01".to_vec(),
        form: nn_proto::ipc::QnameForm::WireFindEnd,
    }])
}

/// Review of #481 (RB3): a request out of the protocol's bounds never
/// reaches the worker — the core refuses it before it sends it, so the
/// worker's refusal (a violation now) is never provoked by the core.
#[test]
fn a_request_out_of_bounds_is_refused_before_it_is_sent() {
    let f = fixture(Script::Honest);
    assert!(tick_until(&f.workers, Health::Ready));
    let big = Request::DnsNames(vec![QnameIn {
        bytes: vec![1; nn_proto::ipc::MAX_QNAME_IN + 1],
        form: nn_proto::ipc::QnameForm::Wire,
    }]);
    let got = f
        .workers
        .request(WorkerKind::Parse, &big, Duration::from_secs(2));
    assert!(matches!(got, Err(WorkerError::Refused(_))), "{got:?}");
    let st = &f.workers.status()[0];
    assert_eq!((st.violations, st.deaths), (0, 0), "{st:?}");
    assert_eq!(st.health, Health::Ready);
    // and the worker serves the next one
    assert!(f
        .workers
        .request(WorkerKind::Parse, &names(), Duration::from_secs(2))
        .is_ok());
}

/// Review of #481 (R14b-2, RB1): a batch of names waits at most
/// `NAMES_TIMEOUT`, well under the connects' wait for the DNS pass
/// (`INGEST_WAIT`): a worker that answers in 100 ms is a hang — killed,
/// signed — and its names have no decode; it never slows the pass to the
/// connects' wait.
#[test]
fn a_slow_worker_is_a_hang_well_before_the_connects_wait() {
    use crate::worker::parse::{ParseClient, ANSWER_TIMEOUT, NAMES_TIMEOUT};
    assert!(
        NAMES_TIMEOUT * 4 < crate::net::dns_ingest::INGEST_WAIT,
        "{NAMES_TIMEOUT:?}"
    );
    // review of #495, D2: and a DNS response's, NN-L-NET-028's barrier
    assert!(
        ANSWER_TIMEOUT * 4 <= crate::net::dns_ingest::INGEST_WAIT,
        "{ANSWER_TIMEOUT:?}"
    );
    let f = fixture(Script::SlowNames);
    assert!(tick_until(&f.workers, Health::Ready));
    let mut parse = ParseClient::new(Some(f.workers.clone()));
    let q = || QnameIn {
        bytes: b"\x07example\x03com\x00".to_vec(),
        form: nn_proto::ipc::QnameForm::Wire,
    };
    let t = Instant::now();
    let got = parse.names(vec![q(), q()]);
    assert!(
        t.elapsed() < Duration::from_millis(100),
        "{:?}",
        t.elapsed()
    );
    assert_eq!(got, vec![None, None]);
    assert_eq!(parse.unparsed, 2);
    let st = &f.workers.status()[0];
    assert_eq!((st.hangs, st.deaths), (1, 1), "{st:?}");
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

/// R14b: a worker started before the deny hooks is registered when they are
/// armed, and its successors at their start.
#[test]
fn roles_armed_later_register_the_running_worker() {
    let early = Arc::new(Recorder::default());
    let reports: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    let r = Arc::clone(&reports);
    let w = Workers::new(Config {
        launcher: Arc::new(Scripted {
            script: Script::DieOnRequest,
            launches: AtomicU32::new(0),
        }),
        roles: early.clone(),
        report: Arc::new(move |s: &str, d: &str| r.lock().push((s.into(), d.into()))),
        kinds: vec![WorkerKind::Parse],
        debug_dir: None,
    });
    assert!(tick_until(&w, Health::Ready));
    let first = w.status()[0].pid.unwrap();
    let armed = Arc::new(Recorder::default());
    w.arm_roles(armed.clone());
    assert_eq!(*armed.registered.lock(), vec![first]);
    // the next worker goes to the armed roles, and the dead one leaves them
    let _ = w.request(WorkerKind::Parse, &names(), Duration::from_secs(2));
    assert_eq!(*armed.evicted.lock(), vec![first]);
    assert!(tick_until(&w, Health::Ready));
    let second = w.status()[0].pid.unwrap();
    assert_eq!(*armed.registered.lock(), vec![first, second]);
    assert_eq!(
        early.evicted.lock().len(),
        0,
        "nothing goes to the earlier roles"
    );
    w.stop();
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
        // review of #481 (R14b-1)
        (Script::RefuseAll, names(), "a checked request refused"),
        (
            Script::EmptyNames,
            names(),
            "an empty name for a name's bytes",
        ),
        (
            Script::EndOffRoot,
            names_find_end(),
            "an end not past a root label",
        ),
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
        // review of #480 (F6): a pass between the hello and the crash,
        // well inside STABLE, clears nothing — a "crash after ready"
        // loop is still disabled
        let before = f.workers.status()[0].failures;
        let later = Duration::from_secs(5);
        assert!(later < PING_EVERY && later < STABLE);
        f.workers.tick(Instant::now() + later);
        assert_eq!(
            f.workers.status()[0].failures,
            before,
            "start {i}: not stable yet"
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
        f.workers.publish(slot, &s);
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

/// Review of #480 (F2, the reviewer's probe as a test): a worker that
/// answers every ping on time and never reads is caught at the second
/// request (its first left unread), and the core never blocks — not the
/// supervisor's pass, not the status.
#[test]
fn a_worker_that_never_reads_is_a_violation_not_a_stall() {
    let f = fixture(Script::NoRead);
    assert!(tick_until(&f.workers, Health::Ready));
    let w = f.workers.clone();
    let ticker = std::thread::spawn(move || {
        for _ in 0..50 {
            w.tick(Instant::now() + PING_EVERY + Duration::from_millis(1));
            if w.status()[0].violations > 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    });
    let end = Instant::now() + Duration::from_secs(10);
    while !ticker.is_finished() {
        assert!(Instant::now() < end, "the supervisor's pass is stuck");
        let t = Instant::now();
        let _ = f.workers.status();
        assert!(t.elapsed() < Duration::from_millis(500), "status() waited");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(ticker.join().unwrap(), "no violation");
    let st = &f.workers.status()[0];
    assert!(st.violations >= 1, "{st:?}");
    assert!(
        f.reports
            .lock()
            .iter()
            .any(|(_, d)| d.contains("left unread")),
        "{:?}",
        f.reports.lock()
    );
}

/// F2: the status is a snapshot — a request holding the worker (a hung
/// one, until its deadline) never holds the status.
#[test]
fn the_status_never_waits_on_a_request() {
    let f = fixture(Script::Hang);
    assert!(tick_until(&f.workers, Health::Ready));
    let w = f.workers.clone();
    let req =
        std::thread::spawn(move || w.request(WorkerKind::Parse, &names(), Duration::from_secs(2)));
    std::thread::sleep(Duration::from_millis(200));
    assert!(!req.is_finished(), "the request is still waiting");
    let t = Instant::now();
    let st = f.workers.status();
    assert!(
        t.elapsed() < Duration::from_millis(100),
        "{:?}",
        t.elapsed()
    );
    assert_eq!(st[0].health, Health::Ready);
    assert!(matches!(req.join().unwrap(), Err(WorkerError::Timeout)));
    assert_eq!(
        f.workers.status()[0].hangs,
        1,
        "published after the request"
    );
}

/// Review of #480 (F3): a worker that exits on its own is evicted from
/// `PROTECTED_PIDS` while its pid is still held (a zombie), reaped after.
#[derive(Default)]
struct EvictProbe {
    /// (pid, the pid still existed at the eviction)
    seen: Mutex<Vec<(u32, bool)>>,
    /// Evictions refused before one succeeds.
    refuse: AtomicU32,
}

impl PidRoles for EvictProbe {
    fn register_worker(&self, _pid: u32) -> Result<(), String> {
        Ok(())
    }
    fn evict(&self, pid: u32) -> Result<(), String> {
        // SAFETY: signal 0: existence only (a zombie exists)
        let exists = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0;
        self.seen.lock().push((pid, exists));
        if self.refuse.load(Ordering::SeqCst) > 0 {
            self.refuse.fetch_sub(1, Ordering::SeqCst);
            return Err("the map refused".into());
        }
        Ok(())
    }
}

struct ShortLived;

impl Launcher for ShortLived {
    fn unavailable(&self) -> Option<String> {
        None
    }
    fn account(&self) -> Option<(u32, u32)> {
        Some((UID, GID))
    }
    fn kernel_landlock_abi(&self) -> u8 {
        level().landlock_abi
    }
    fn launch(&self, _kind: WorkerKind) -> std::io::Result<Spawned> {
        let child = Command::new("sleep")
            .arg("0.3")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let (ours, theirs) = transport::socketpair()?;
        let pid = child.id();
        // the channel stays open (a peer thread holds it): the death is
        // found by the pass, not by the channel
        std::thread::spawn(move || run_script(Script::Honest, theirs, pid));
        Ok(Spawned {
            child,
            sock: ours,
            stderr: None,
        })
    }
}

fn exists(pid: u32) -> bool {
    // SAFETY: signal 0: existence only.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[test]
fn a_dead_worker_s_pid_is_evicted_before_it_is_reaped() {
    let probe = Arc::new(EvictProbe::default());
    let workers = Workers::new(Config {
        launcher: Arc::new(ShortLived),
        roles: probe.clone(),
        report: Arc::new(|_: &str, _: &str| {}),
        kinds: vec![WorkerKind::Parse],
        debug_dir: None,
    });
    assert!(tick_until(&workers, Health::Ready));
    let end = Instant::now() + Duration::from_secs(5);
    while Instant::now() < end && probe.seen.lock().is_empty() {
        workers.tick(Instant::now());
        std::thread::sleep(Duration::from_millis(20));
    }
    let seen = probe.seen.lock().clone();
    workers.stop();
    let (pid, held) = *seen.first().expect("an eviction");
    assert!(
        held,
        "pid {pid} was free (reaped) at its eviction: {seen:?}"
    );
    assert!(!exists(pid), "reaped after");
}

#[test]
fn a_pid_that_cannot_be_evicted_is_kept_unreaped_and_reported() {
    let probe = Arc::new(EvictProbe::default());
    probe.refuse.store(3, Ordering::SeqCst);
    let reports: Arc<Mutex<Vec<String>>> = Arc::default();
    let r = Arc::clone(&reports);
    let workers = Workers::new(Config {
        launcher: Arc::new(ShortLived),
        roles: probe.clone(),
        report: Arc::new(move |_: &str, d: &str| r.lock().push(d.into())),
        kinds: vec![WorkerKind::Parse],
        debug_dir: None,
    });
    assert!(tick_until(&workers, Health::Ready));
    let end = Instant::now() + Duration::from_secs(5);
    while Instant::now() < end && probe.seen.lock().len() < 2 {
        workers.tick(Instant::now());
        std::thread::sleep(Duration::from_millis(20));
    }
    let pid = probe.seen.lock()[0].0;
    // refused: its pid still held (a zombie), reported once
    assert!(exists(pid), "the pid must stay taken");
    let said: Vec<String> = reports
        .lock()
        .iter()
        .filter(|d| d.contains("could not be taken out of PROTECTED_PIDS"))
        .cloned()
        .collect();
    assert_eq!(said.len(), 1, "{:?}", reports.lock());
    // evicted at a later pass: then reaped
    let end = Instant::now() + Duration::from_secs(5);
    while Instant::now() < end && exists(pid) {
        workers.tick(Instant::now());
        std::thread::sleep(Duration::from_millis(20));
    }
    workers.stop();
    assert!(!exists(pid), "reaped once evicted");
    assert!(probe.seen.lock().iter().all(|(p, held)| *p != pid || *held));
}

/// Review of #480 (F12): a worker that burns a CPU while asked nothing but
/// pings is a hang; one that sleeps is not.
struct Spinner {
    spin: bool,
}

impl Launcher for Spinner {
    fn unavailable(&self) -> Option<String> {
        None
    }
    fn account(&self) -> Option<(u32, u32)> {
        Some((UID, GID))
    }
    fn kernel_landlock_abi(&self) -> u8 {
        level().landlock_abi
    }
    fn launch(&self, _kind: WorkerKind) -> std::io::Result<Spawned> {
        let script = if self.spin {
            "while :; do :; done"
        } else {
            "sleep 600"
        };
        let child = Command::new("sh")
            .arg("-c")
            .arg(script)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let (ours, theirs) = transport::socketpair()?;
        let pid = child.id();
        std::thread::spawn(move || run_script(Script::Honest, theirs, pid));
        Ok(Spawned {
            child,
            sock: ours,
            stderr: None,
        })
    }
}

#[test]
fn a_spinning_worker_is_killed_as_a_hang() {
    for spin in [true, false] {
        let reports: Arc<Mutex<Vec<String>>> = Arc::default();
        let r = Arc::clone(&reports);
        let workers = Workers::new(Config {
            launcher: Arc::new(Spinner { spin }),
            roles: Arc::new(NoPidRoles),
            report: Arc::new(move |_: &str, d: &str| r.lock().push(d.into())),
            kinds: vec![WorkerKind::Parse],
            debug_dir: None,
        });
        assert!(tick_until(&workers, Health::Ready));
        let end = Instant::now() + SPIN_WINDOW * 4;
        while Instant::now() < end && workers.status()[0].hangs == 0 {
            workers.tick(Instant::now());
            std::thread::sleep(Duration::from_millis(20));
        }
        let st = workers.status()[0].clone();
        workers.stop();
        if spin {
            assert_eq!(st.hangs, 1, "{st:?}");
            assert!(
                reports.lock().iter().any(|d| d.contains("spinning")),
                "{:?}",
                reports.lock()
            );
        } else {
            assert_eq!(st.hangs, 0, "a sleeping worker is no spin: {st:?}");
        }
    }
}

/// Review of #480 (F4): a worker's stderr reaches the log escaped, cut, and
/// at most STDERR_LINES_PER_MINUTE lines a minute.
#[test]
fn a_worker_s_stderr_is_escaped_cut_and_rate_limited() {
    assert_eq!(escape_line(b"plain line"), "plain line");
    assert_eq!(escape_line(b"<3>forged\x1b[31m"), "<3>forged\\x1b[31m");
    assert_eq!(escape_line(b"a\\b"), "a\\x5cb");
    let long = escape_line(&[b'x'; 1000]);
    assert!(
        long.len() <= STDERR_LINE_MAX + '…'.len_utf8(),
        "{}",
        long.len()
    );
    // a pipe of the worker's, drained by a pass
    let f = fixture(Script::Honest);
    assert!(tick_until(&f.workers, Health::Ready));
    let mut fds = [0; 2];
    // SAFETY: pipe2 into a local array.
    assert_eq!(
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK) },
        0
    );
    // SAFETY: the kernel just returned these descriptors.
    let (r, w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    {
        let slot = f.workers.slot(WorkerKind::Parse).unwrap();
        slot.s.lock().stderr = Some(r);
    }
    let lines = STDERR_LINES_PER_MINUTE as usize + 7;
    let mut text = Vec::new();
    for i in 0..lines {
        text.extend_from_slice(format!("line {i}\n").as_bytes());
    }
    // one line far past the cut, no newline yet
    text.extend_from_slice(&[b'y'; 3 * STDERR_LINE_MAX]);
    // SAFETY: write to our pipe.
    unsafe { libc::write(w.as_raw_fd(), text.as_ptr().cast(), text.len()) };
    f.workers.tick(Instant::now());
    let slot = f.workers.slot(WorkerKind::Parse).unwrap();
    let s = slot.s.lock();
    assert_eq!(s.err_lines, STDERR_LINES_PER_MINUTE);
    // the 7 extra lines and the long one's two full cuts
    assert_eq!(s.err_dropped, 7 + 2);
    assert!(s.err_partial.len() <= STDERR_LINE_MAX);
}

/// PDEATHSIG is the forking thread's: production's launcher starts a worker
/// from the supervisor's thread only.
#[test]
fn a_worker_is_started_from_the_supervisor_s_thread_only() {
    let launcher = ImageLauncher {
        image: None,
        account: Err("none".into()),
        extra_args: vec![],
    };
    let err = launcher.launch(WorkerKind::Parse).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    let launcher = Arc::new(launcher);
    let l = Arc::clone(&launcher);
    let err = std::thread::Builder::new()
        .name(SUPERVISOR_THREAD.into())
        .spawn(move || l.launch(WorkerKind::Parse).unwrap_err())
        .unwrap()
        .join()
        .unwrap();
    // past the thread's check: no image here
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "{err}");
}

/// Review of #480 (F7): the kernel's view of a worker against its word.
#[test]
fn a_worker_s_process_is_checked_against_its_declaration() {
    let l = level();
    let ok = format!(
        "Name:\tnn-worker-parse\nUid:\t{u}\t{u}\t{u}\t{u}\nGid:\t{g}\t{g}\t{g}\t{g}\n\
         Groups:\t\nNoNewPrivs:\t1\nSeccomp:\t2\nCapInh:\t0000000000000000\n\
         CapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\n\
         CapAmb:\t0000000000000000\n",
        u = l.uid,
        g = l.gid
    );
    assert_eq!(verify_proc(&ok, &l), Ok(()));
    for (from, to) in [
        (
            format!("Uid:\t{u}\t{u}\t{u}\t{u}", u = l.uid),
            format!("Uid:\t{u}\t0\t{u}\t{u}", u = l.uid),
        ),
        ("Groups:\t".to_string(), "Groups:\t27".to_string()),
        ("NoNewPrivs:\t1".to_string(), "NoNewPrivs:\t0".to_string()),
        ("Seccomp:\t2".to_string(), "Seccomp:\t0".to_string()),
        (
            "CapEff:\t0000000000000000".to_string(),
            "CapEff:\t0000000000000020".to_string(),
        ),
        (
            "CapAmb:\t0000000000000000".to_string(),
            "CapAmb:\t0000000000000001".to_string(),
        ),
    ] {
        let bad = ok.replace(&from, &to);
        assert_ne!(bad, ok, "{from}");
        assert!(verify_proc(&bad, &l).is_err(), "{to}");
    }
    assert!(verify_proc("Name:\tx\n", &l).is_err());
}

/// F7: an honest hello the launcher's view contradicts — the kernel's
/// Landlock ABI is another, or the process's `/proc` is not what it
/// declared — is refused, and the worker never serves.
struct Contradicted {
    inner: Scripted,
    kernel_abi: u8,
    proc_ok: bool,
}

impl Launcher for Contradicted {
    fn unavailable(&self) -> Option<String> {
        None
    }
    fn account(&self) -> Option<(u32, u32)> {
        Some((UID, GID))
    }
    fn kernel_landlock_abi(&self) -> u8 {
        self.kernel_abi
    }
    fn launch(&self, kind: WorkerKind) -> std::io::Result<Spawned> {
        self.inner.launch(kind)
    }
    fn verify(&self, _pid: u32, _declared: &SandboxLevel) -> Result<(), String> {
        if self.proc_ok {
            Ok(())
        } else {
            Err("CapEff 0000000000000020".into())
        }
    }
}

#[test]
fn a_hello_the_kernel_or_proc_contradicts_is_refused() {
    let abi = level().landlock_abi;
    for (kernel_abi, proc_ok, want) in [
        (abi, true, None),
        (abi + 2, true, Some("landlock ABI")),
        (abi, false, Some("its process is not what it declared")),
    ] {
        let reports: Arc<Mutex<Vec<String>>> = Arc::default();
        let r = Arc::clone(&reports);
        let workers = Workers::new(Config {
            launcher: Arc::new(Contradicted {
                inner: Scripted {
                    script: Script::Honest,
                    launches: AtomicU32::new(0),
                },
                kernel_abi,
                proc_ok,
            }),
            roles: Arc::new(NoPidRoles),
            report: Arc::new(move |_: &str, d: &str| r.lock().push(d.into())),
            kinds: vec![WorkerKind::Parse],
            debug_dir: None,
        });
        // ready, or refused: whichever comes first
        let end = Instant::now() + Duration::from_secs(8);
        let mut st = workers.status()[0].clone();
        while Instant::now() < end && st.health != Health::Ready && st.violations == 0 {
            workers.tick(Instant::now());
            st = workers.status()[0].clone();
            std::thread::sleep(Duration::from_millis(10));
        }
        workers.stop();
        match want {
            None => assert_eq!(st.health, Health::Ready, "{st:?}"),
            Some(why) => {
                assert!(st.health != Health::Ready && st.violations >= 1, "{st:?}");
                assert!(
                    reports.lock().iter().any(|d| d.contains(why)),
                    "{why}: {:?}",
                    reports.lock()
                );
            }
        }
    }
}

/// F7: the production launcher reads the worker's `/proc/<pid>/status`
/// itself — here this test process's, which is no worker (no seccomp
/// filter, no `no_new_privs`), and a pid that does not exist.
#[test]
fn the_image_launcher_reads_the_process_s_own_status() {
    let launcher = ImageLauncher {
        image: None,
        account: Err("none".into()),
        extra_args: Vec::new(),
    };
    // SAFETY: getuid and getgid have no preconditions.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let declared = SandboxLevel {
        uid,
        gid,
        ..level()
    };
    let me = launcher.verify(std::process::id(), &declared);
    assert!(me.is_err(), "{me:?}");
    let gone = launcher.verify(u32::MAX - 1, &declared);
    assert!(
        gone.as_ref().is_err_and(|e| e.contains("unreadable")),
        "{gone:?}"
    );
}
