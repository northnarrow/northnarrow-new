//! Lot 353 (re-check 4 of #563, R4-1): the decision thread's facts under a
//! mount laid over the agent's own descriptors in `/proc`.
//!
//! The decision thread's seccomp filter refuses `openat2`, so its reads
//! beneath the anchored `/proc` root walk one name at a time, each name's
//! mount checked. On 8c1c5d12 the walk's last step — the file opened again
//! with the caller's flags — went by name through `self/fd/N`, a plain
//! `openat` that crossed whatever was mounted on `/proc/<pid>/fd`: a tmpfs
//! there gave the decision the cover's files for every fact (the uid, the
//! cgroup, the `Tgid` the marks are read for), and a FUSE there held it.
//! The reopen goes through the thread's own `thread-self/fd` now, each name
//! of it checked, and what it opened is compared with the descriptor the
//! walk reached (mount and inode).
//!
//! And (P2) a mount laid below `/proc/<pid>` of another process: its facts
//! are not read — and said to be unread ([`ActorFacts::unread`]), not taken
//! for a process no exemption covers.
//!
//! A test binary of its own, with this one test: the run forks (the user
//! namespace), and the child anchors the views in its own namespace — the
//! process-wide views must not have been taken before.

use std::sync::mpsc;
use std::time::Duration;

use antitamper_bpf::kernel_roots;
use nn_core::decision::rule_policy::{ActorFacts, ExemptionFact};
use northnarrow_agent::decision_host_linux::ProcFacts;

/// What the covers hold in place of every descriptor: a status naming
/// another uid, and a text that is no kernel's release.
const FAKE: &[u8] = b"Uid:\t4242\t4242\t4242\t4242\nFAKE-FACT\n";

/// A tmpfs over `at` holding [`FAKE`] under the names of the first
/// descriptors; `false` when it could not be laid or did not take.
fn cover(at: &str) -> bool {
    let c = std::ffi::CString::new(at).unwrap();
    // SAFETY: NUL-terminated strings, no data.
    let rc = unsafe {
        libc::mount(
            c"none".as_ptr(),
            c.as_ptr(),
            c"tmpfs".as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        eprintln!(
            "missing here: a tmpfs over {at}: {}",
            std::io::Error::last_os_error()
        );
        return false;
    }
    for n in 0..1024 {
        let _ = std::fs::write(format!("{at}/{n}"), FAKE);
    }
    std::fs::read(format!("{at}/0")).is_ok_and(|b| b == FAKE)
}

/// The child's run (in its namespaces): 0 when the decision's reads hold,
/// 99 when a prerequisite is missing here, another code naming the step.
fn run() -> i32 {
    let _ = kernel_roots::init();
    if kernel_roots::symlink_metadata("/proc/self").is_err() {
        eprintln!("missing here: /proc not anchored");
        return 99;
    }
    let me = std::process::id();
    let Some(uid) = ProcFacts::default().uid(me) else {
        return 10;
    };
    let Ok(release) = std::fs::read("/proc/sys/kernel/osrelease") else {
        return 10;
    };
    // under the filter, before any cover: the facts as by path
    let Some(first) = Decision::start(me) else {
        return 11;
    };
    if first.ask() != Some((Some(uid), Some(release.clone()))) {
        return 12;
    }
    // a tmpfs over the process's `fd` directory: never on the walk — a
    // decision thread whose first read comes after it (nothing kept)
    if !cover(&format!("/proc/{me}/fd")) {
        return 99;
    }
    let Some(second) = Decision::start(me) else {
        return 11;
    };
    for (d, which) in [(&second, "a new"), (&first, "the first")] {
        match d.ask() {
            Some((u, r)) if u == Some(uid) && r.as_deref() == Some(&release[..]) => {}
            Some((u, r)) if u == Some(4242) || r.as_deref() == Some(FAKE) => {
                eprintln!("{which} decision thread read the tmpfs over /proc/<pid>/fd");
                return 13;
            }
            None => {
                eprintln!("{which} decision thread did not answer under the tmpfs");
                return 14;
            }
            Some(other) => {
                eprintln!("{which} decision thread under the tmpfs: {other:?}");
                return 15;
            }
        }
        // opened, not read through a crossing of the cover: the reopen
        // walks this thread's own descriptor directory
        if !d.opens() {
            eprintln!("{which} decision thread's open under the tmpfs over /proc/<pid>/fd");
            return 20;
        }
    }
    // a tmpfs over a decision thread's own `fd` directory, laid before its
    // first read: what it reads is the kernel's or nothing — never the
    // cover's
    let Some(third) = Decision::start(me) else {
        return 11;
    };
    if !cover(&format!("/proc/{me}/task/{}/fd", third.tid)) {
        return 99;
    }
    match third.ask() {
        Some((u, r))
            if u.is_none_or(|u| u == uid) && r.as_deref().is_none_or(|r| r == &release[..]) => {}
        Some(_) => {
            eprintln!("the decision read the tmpfs over its own /proc/<pid>/task/<tid>/fd");
            return 16;
        }
        None => {
            eprintln!("the decision did not answer under the tmpfs over its own fd directory");
            return 17;
        }
    }
    // (P2) a mount below /proc/<pid> of another process: its uid not
    // read, and said to be unread — before the cover, read
    let Ok(mut sleeper) = std::process::Command::new("/usr/bin/sleep")
        .arg("60")
        .spawn()
    else {
        eprintln!("missing here: no /usr/bin/sleep");
        return 99;
    };
    let other = sleeper.id();
    let before = first.ask_of(Some(other)).and_then(|(_, _, o, _)| o);
    let laid = cover(&format!("/proc/{other}"));
    let after = first.ask_of(Some(other)).and_then(|(_, _, o, _)| o);
    let _ = sleeper.kill();
    let _ = sleeper.wait();
    if !laid {
        return 99;
    }
    if before != Some((Some(uid), None)) {
        eprintln!("before the cover: {before:?}");
        return 18;
    }
    match after {
        Some((None, Some(why))) if why.contains(&format!("/proc/{other}/status")) => {}
        other => {
            eprintln!("under the cover: {other:?}");
            return 19;
        }
    }
    0
}

/// A thread in the decision's role, under its filter (no `openat2`): its
/// tid, and one round of reads per request.
struct Decision {
    tid: i32,
    go: mpsc::Sender<Option<u32>>,
    out: mpsc::Receiver<Reads>,
}

impl Decision {
    fn start(me: u32) -> Option<Decision> {
        let (tid_tx, tid_rx) = mpsc::channel::<Option<i32>>();
        let (go_tx, go_rx) = mpsc::channel::<Option<u32>>();
        let (out_tx, out_rx) = mpsc::channel::<Reads>();
        std::thread::Builder::new()
            .name("nn-decision".into())
            .spawn(move || {
                let e = nn_linux::caps::enter(nn_linux::caps::Role::Decision);
                if !e.as_ref().is_ok_and(|e| e.filter == Some(Ok(()))) {
                    eprintln!("the decision's filter: {e:?}");
                    let _ = tid_tx.send(None);
                    return;
                }
                // SAFETY: gettid has no preconditions.
                let _ = tid_tx.send(Some(unsafe { libc::gettid() }));
                while let Ok(other) = go_rx.recv() {
                    let facts = ProcFacts::default();
                    let own = (
                        facts.uid(me),
                        kernel_roots::read("/proc/sys/kernel/osrelease", 4096).ok(),
                    );
                    let other = other.map(|p| (facts.uid(p), facts.unread(p, ExemptionFact::Uid)));
                    // the open a caller keeps (no crossing to fall back on)
                    let opened =
                        kernel_roots::open(format!("/proc/{me}/status"), libc::O_RDONLY).is_ok();
                    let _ = out_tx.send((own.0, own.1, other, opened));
                }
            })
            .ok()?;
        let tid = tid_rx.recv().ok()??;
        Some(Decision {
            tid,
            go: go_tx,
            out: out_rx,
        })
    }

    /// Its round: its own uid and the kernel's release, and `other`'s uid
    /// with why it is unread.
    fn ask_of(&self, other: Option<u32>) -> Option<Reads> {
        self.go.send(other).ok()?;
        self.out.recv_timeout(Duration::from_secs(10)).ok()
    }

    fn ask(&self) -> Option<(Option<u32>, Option<Vec<u8>>)> {
        self.ask_of(None).map(|(u, r, _, _)| (u, r))
    }

    /// Whether its `kernel_roots::open` of its process's status opens.
    fn opens(&self) -> bool {
        self.ask_of(None).is_some_and(|(_, _, _, o)| o)
    }
}

/// What the decision thread read: its own uid, the kernel's release,
/// another process's uid with why it is unread, and whether its process's
/// status opened.
type Reads = (
    Option<u32>,
    Option<Vec<u8>>,
    Option<(Option<u32>, Option<String>)>,
    bool,
);

/// Lot 353 (re-check 4 of #563, R4-1; named): the decision thread's
/// facts, read under its filter (no `openat2`), are never read through a
/// tmpfs laid over `/proc/<pid>/fd` — on 8c1c5d12 its uid was the cover's
/// (4242) and `/proc/sys/kernel/osrelease` the cover's text — nor through
/// one over its own `/proc/<pid>/task/<tid>/fd`: the kernel's answer or
/// none, failing closed. And (P2) a mount below another process's
/// `/proc/<pid>`: its uid not read, and said to be unread.
#[test]
fn the_decision_s_facts_are_never_read_through_a_mount_over_its_descriptors() {
    let rc = nn_linux::fuse_testing::in_userns(run);
    if let Some(rc) = nn_linux::fuse_testing::ran(rc) {
        assert_eq!(
            rc, 0,
            "the decision's reads under a cover (the child's line above)"
        );
    }
}
