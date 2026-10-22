//! The agent's end (lab PR 223): the supervisor starts the real scanner as
//! a given user, sees it ready, hands it a file, notices its death and
//! starts it again.

use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use nn_proto::execq::{encode_config, HashEntry, ScanConfig, ScanRequest, ScanVerdict};
use northnarrow_scan::supervisor::{lookup_user, ScanUser, ScannerEvent, Supervisor};
use sha2::{Digest, Sha256};

fn me() -> ScanUser {
    // SAFETY: getuid/getgid have no preconditions.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    ScanUser {
        name: "test".into(),
        uid,
        gid,
    }
}

fn wait_for(s: &mut Supervisor, mut want: impl FnMut(&ScannerEvent) -> bool) -> ScannerEvent {
    let until = Instant::now() + Duration::from_secs(10);
    while Instant::now() < until {
        for e in s.poll(Instant::now()) {
            if want(&e) {
                return e;
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("no matching scanner event");
}

#[test]
fn started_as_its_user_ready_scanning_and_restarted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("payload");
    let content = b"payload bytes for the block list";
    std::fs::File::create(&path)
        .unwrap()
        .write_all(content)
        .unwrap();
    let cfg = ScanConfig {
        block: vec![HashEntry {
            sha256: Sha256::digest(content).into(),
            label: "lab".into(),
        }],
        ..ScanConfig::default()
    };
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_northnarrow-scan"));
    let mut s = Supervisor::new(exe, me(), encode_config(&cfg).unwrap());
    assert!(s.start_if_due(Instant::now()).unwrap());
    let ScannerEvent::Ready(h) = wait_for(&mut s, |e| matches!(e, ScannerEvent::Ready(_))) else {
        unreachable!()
    };
    assert_eq!(h.uid, me().uid);
    assert!(s.is_ready());
    let f = std::fs::File::open(&path).unwrap();
    let req = ScanRequest {
        id: 42,
        class: 0,
        path_hint: String::new(),
    };
    s.send(&req, f.as_raw_fd()).unwrap();
    let ScannerEvent::Result(r) = wait_for(&mut s, |e| matches!(e, ScannerEvent::Result(_))) else {
        unreachable!()
    };
    assert_eq!((r.id, r.verdict), (42, ScanVerdict::Malicious));

    // killed from outside: seen, and started again at once
    let pid = s.pid().unwrap();
    // SAFETY: signalling our own child.
    unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    let ScannerEvent::Died { why } = wait_for(&mut s, |e| matches!(e, ScannerEvent::Died { .. }))
    else {
        unreachable!()
    };
    assert!(why.contains("signal 9"), "{why}");
    assert!(!s.is_ready() && !s.is_running());
    assert!(s.send(&req, f.as_raw_fd()).is_err(), "nothing to send to");
    assert!(
        s.next_start().unwrap() <= Instant::now(),
        "first restart without delay"
    );
    assert!(s.start_if_due(Instant::now()).unwrap());
    wait_for(&mut s, |e| matches!(e, ScannerEvent::Ready(_)));
    assert_eq!(s.counts(), (2, 1));
}

#[test]
fn a_missing_binary_backs_off() {
    let mut s = Supervisor::new(
        PathBuf::from("/nonexistent/northnarrow-scan"),
        me(),
        Vec::new(),
    );
    let t = Instant::now();
    assert!(s.start_if_due(t).is_err());
    assert!(s.start_if_due(t).is_err(), "first retry is immediate");
    assert!(s.next_start().unwrap() > t, "then it waits");
    assert!(!s.start_if_due(t).unwrap(), "not due yet");
}

#[test]
fn root_and_unknown_users_are_refused() {
    assert!(lookup_user("root").unwrap_err().contains("root"));
    assert!(lookup_user("nn-no-such-user-xyz")
        .unwrap_err()
        .contains("no user"));
}
