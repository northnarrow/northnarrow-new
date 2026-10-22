//! The scanner as the agent runs it (lab PR 223): a child process with the
//! channel on descriptor 3, configured through a sealed memfd, confined,
//! answering scans of descriptors it is handed.

use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

use nn_proto::execq::{
    decode, encode, encode_config, FromScanner, HashEntry, ScanConfig, ScanRequest, ScanVerdict,
    ToScanner, MAX_PACKET, PROTOCOL_VERSION,
};
use northnarrow_scan::ipc;
use sha2::{Digest, Sha256};

fn spawn() -> (Child, OwnedFd) {
    let (ours, theirs) = ipc::socketpair().unwrap();
    let raw = theirs.as_raw_fd();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_northnarrow-scan"));
    cmd.stdin(Stdio::null()).stdout(Stdio::null());
    // SAFETY: dup2 only, in the child before exec.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(raw, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn().unwrap();
    drop(theirs);
    (child, ours)
}

fn configure(sock: &OwnedFd, cfg: &ScanConfig) -> FromScanner {
    let bytes = encode_config(cfg).unwrap();
    let memfd = ipc::sealed_memfd("nn-scan-config", &bytes).unwrap();
    let msg = encode(&ToScanner::Configure {
        version: PROTOCOL_VERSION,
        config_len: bytes.len() as u64,
    })
    .unwrap();
    ipc::send(sock.as_raw_fd(), &msg, Some(memfd.as_raw_fd())).unwrap();
    recv(sock)
}

fn recv(sock: &OwnedFd) -> FromScanner {
    let mut buf = vec![0u8; MAX_PACKET];
    let p = ipc::recv(sock.as_raw_fd(), &mut buf, false).unwrap();
    assert!(
        p.len > 0,
        "scanner closed the channel (killed by its filter?)"
    );
    decode(&buf[..p.len]).unwrap()
}

fn scan(sock: &OwnedFd, id: u64, fd: Option<&std::fs::File>) -> FromScanner {
    let msg = encode(&ToScanner::Scan(ScanRequest {
        id,
        class: common::wire::execq::class::HOME,
        path_hint: "/home/u/x".into(),
    }))
    .unwrap();
    ipc::send(sock.as_raw_fd(), &msg, fd.map(|f| f.as_raw_fd())).unwrap();
    recv(sock)
}

#[test]
fn configured_confined_and_answering() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("nn-test-elf");
    let content = b"\x7fELF\x02\x01\x01 northnarrow lab test binary";
    std::fs::File::create(&bad)
        .unwrap()
        .write_all(content)
        .unwrap();
    let sha: [u8; 32] = Sha256::digest(content).into();
    let (mut child, sock) = spawn();
    let cfg = ScanConfig {
        block: vec![HashEntry {
            sha256: sha,
            label: "nn-lab-test-elf".into(),
        }],
        ..ScanConfig::default()
    };
    match configure(&sock, &cfg) {
        FromScanner::Ready(h) => {
            assert!(h.seccomp);
            assert_eq!(h.block_entries, 1);
            assert_eq!(h.version, PROTOCOL_VERSION);
            assert_eq!(h.yara, "none");
        }
        other => panic!("not ready: {other:?}"),
    }
    // a block-listed file, by descriptor
    let f = std::fs::File::open(&bad).unwrap();
    match scan(&sock, 1, Some(&f)) {
        FromScanner::Result(r) => {
            assert_eq!(r.id, 1);
            assert_eq!(r.verdict, ScanVerdict::Malicious);
            assert_eq!(r.sha256, sha);
            assert_eq!(r.reasons[0].detail, "nn-lab-test-elf");
        }
        other => panic!("{other:?}"),
    }
    // the scanner's own binary: a real ELF, clean
    let me = std::fs::File::open(env!("CARGO_BIN_EXE_northnarrow-scan")).unwrap();
    match scan(&sock, 2, Some(&me)) {
        FromScanner::Result(r) => {
            assert!(r.format.starts_with("elf64-"), "{}", r.format);
            assert_ne!(r.verdict, ScanVerdict::Malicious);
        }
        other => panic!("{other:?}"),
    }
    // a directory and no descriptor at all are refused, not fatal
    let d = std::fs::File::open(dir.path()).unwrap();
    assert!(matches!(
        scan(&sock, 3, Some(&d)),
        FromScanner::Refused { id: 3, .. }
    ));
    assert!(matches!(
        scan(&sock, 4, None),
        FromScanner::Refused { id: 4, .. }
    ));
    // the agent closes the channel: the scanner exits 0
    drop(sock);
    let st = child.wait().unwrap();
    assert!(st.success(), "{st:?}");
}

#[test]
fn a_protocol_mismatch_or_a_bad_argument_ends_it() {
    let (mut child, sock) = spawn();
    let msg = encode(&ToScanner::Configure {
        version: PROTOCOL_VERSION + 1,
        config_len: 0,
    })
    .unwrap();
    ipc::send(sock.as_raw_fd(), &msg, None).unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(2));
    let st = Command::new(env!("CARGO_BIN_EXE_northnarrow-scan"))
        .arg("--nope")
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(st.code(), Some(2));
}
