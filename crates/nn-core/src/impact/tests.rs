//! Lab PR 225: the ransomware tracker — two shapes of one actor are
//! decisive, one is not, trusted writers never count.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nn_model::{Event, FileBurstKind};
use parking_lot::Mutex;
use tempfile::TempDir;

use super::entropy::{Sample, Sampler};
use super::*;
use crate::posture::host::testing::TestHost as H;

// R08b (lab PR 251): the tracker on the portable test host (its sampler
// of real files is the agent's, and the tests that read files through it
// are the agent's: `impact::host_tests`).
type AuthSessionTracker = crate::posture::lineage::AuthSessionTracker<H>;
type ProgramOwners = super::trust::ProgramOwners<H>;
type RansomTracker = super::RansomTracker<H>;

const S: u64 = 1_000_000_000;
const T0: u64 = 1_000 * S;

/// A sampler with fixed answers by path prefix; counts its calls.
#[derive(Default)]
struct Fixed {
    answers: Mutex<HashMap<String, Sample>>,
    calls: AtomicU32,
}

impl Fixed {
    fn high(prefix: &str) -> Arc<Self> {
        let f = Self::default();
        f.answers.lock().insert(
            prefix.to_string(),
            Sample {
                examined: 4,
                high: 4,
                containers: 0,
            },
        );
        Arc::new(f)
    }
    fn low() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

impl Sampler for Fixed {
    fn sample_copies(&self, copy: &str, _suffix: &str, since: Duration) -> Sample {
        self.sample(copy, since)
    }
    fn sample(&self, path: &str, _since: Duration) -> Sample {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.answers
            .lock()
            .iter()
            .find(|(p, _)| path.starts_with(p.as_str()))
            .map(|(_, s)| s.clone())
            .unwrap_or(Sample {
                examined: 4,
                high: 0,
                containers: 0,
            })
    }
}

/// A host whose package database installed `/usr/bin/*` and `/usr/sbin/*`
/// (the dpkg lists of a fixture root) and whose lineage tracker knows a
/// login shell (200, from sshd 150).
struct Host {
    _proc: TempDir,
    root: TempDir,
    lineage: AuthSessionTracker,
}

impl Host {
    fn new() -> Self {
        let proc = TempDir::new().unwrap();
        let root = TempDir::new().unwrap();
        let info = root.path().join("var/lib/dpkg/info");
        std::fs::create_dir_all(&info).unwrap();
        std::fs::write(root.path().join("var/lib/dpkg/status"), "Package: x\n").unwrap();
        std::fs::write(
            info.join("base.list"),
            "/usr/bin/bash\n/usr/sbin/sshd\n/usr/bin/tar\n/usr/bin/mv\n/usr/bin/rsync\n\
             /usr/bin/python3\n/usr/bin/git\n",
        )
        .unwrap();
        let lineage = AuthSessionTracker::new(proc.path());
        lineage.ingest_exec(150, 1, "/usr/sbin/sshd", &["sshd".into()], S, S, 0);
        lineage.ingest_exec(
            200,
            150,
            "/usr/bin/bash",
            &["bash".into()],
            2 * S,
            2 * S,
            1000,
        );
        Self {
            _proc: proc,
            root,
            lineage,
        }
    }

    fn exec(&self, pid: u32, ppid: u32, exe: &str, argv: &[&str]) {
        let argv: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
        self.lineage.ingest_exec(
            pid,
            ppid,
            exe,
            &argv,
            10 * S + pid as u64,
            10 * S + pid as u64,
            1000,
        );
    }

    fn tracker(&self, sampler: Arc<Fixed>) -> RansomTracker {
        RansomTracker::with(
            self.lineage.clone(),
            ProgramOwners::new(self.root.path()),
            sampler,
        )
    }
}

/// A test's own tree: `w` inside its own `TempDir`, so that what the copy
/// sampler reads beside a copy in `w` (the `TempDir`) and below it is this
/// test's alone — never the trees of the tests running beside it in the
/// shared temporary directory ([`super::entropy::sample_copies_dir`]).
fn sandbox() -> (TempDir, PathBuf) {
    let t = TempDir::new().unwrap();
    let w = t.path().join("w");
    std::fs::create_dir(&w).unwrap();
    (t, w)
}

fn rewrites(pid: u32, ts: u64, file: &str) -> Event {
    Event::MassWrite {
        pid,
        uid: 1000,
        comm: "python3".into(),
        count: 20,
        filename: file.into(),
        timestamp_ns: ts,
        overwrites: true,
        cgroup_window: false,
    }
}

fn new_files(pid: u32, ts: u64, file: &str) -> Event {
    Event::MassWrite {
        pid,
        uid: 1000,
        comm: "python3".into(),
        count: 20,
        filename: file.into(),
        timestamp_ns: ts,
        overwrites: false,
        cgroup_window: false,
    }
}

fn renames(pid: u32, ts: u64, file: &str, appended: u32, sources: u32) -> Event {
    Event::FileBurst {
        pid,
        uid: 1000,
        comm: "python3".into(),
        kind: FileBurstKind::RenameExtension,
        count: 20,
        appended,
        sources,
        filename: file.into(),
        timestamp_ns: ts,
    }
}

fn unlinks(pid: u32, ts: u64, file: &str) -> Event {
    Event::FileBurst {
        pid,
        uid: 1000,
        comm: "python3".into(),
        kind: FileBurstKind::Unlink,
        count: 20,
        appended: 0,
        sources: 0,
        filename: file.into(),
        timestamp_ns: ts,
    }
}

const SIM: &str = "/srv/nn-malsim/ransom-sim.py";

/// MS-23, in place: the rewrites, and the files they left behind are
/// ciphertext — decisive at the rewrite crossing itself.
#[test]
fn rewrites_with_ciphertext_left_behind_are_decisive() {
    let h = Host::new();
    h.exec(300, 200, "/usr/bin/python3", &["python3", SIM]);
    let t = h.tracker(Fixed::high("/srv/nn-malsim/"));
    let a = t.assess(&rewrites(300, T0, "/srv/nn-malsim/f020")).unwrap();
    assert!(a.decisive, "{a:?}");
    assert_eq!(a.actor, 300);
    assert_eq!(a.program, SIM);
    assert!(a.trusted.is_none());
    let shapes: Vec<Signal> = a.signals.iter().map(|(s, _)| *s).collect();
    assert_eq!(shapes, vec![Signal::Rewrites, Signal::Entropy]);
    assert_eq!(t.counts().decisive, 1);
}

/// MS-23 when the originals were not rewritten yet at the crossing: the
/// rewrites alone are one shape (the posture's ENGAGED, no verdict); the
/// renames to `.locked` that follow make two.
#[test]
fn one_shape_is_not_decisive_and_a_second_one_is() {
    let h = Host::new();
    h.exec(300, 200, "/usr/bin/python3", &["python3", SIM]);
    let t = h.tracker(Fixed::low());
    let a = t.assess(&rewrites(300, T0, "/srv/nn-malsim/f020")).unwrap();
    assert!(!a.decisive);
    assert_eq!(a.added, vec![Signal::Rewrites]);
    let b = t
        .assess(&renames(
            300,
            T0 + 5 * S,
            "/srv/nn-malsim/f020.locked",
            20,
            0,
        ))
        .unwrap();
    assert!(b.decisive, "{b:?}");
    assert!(b.rename_burst);
    assert!(b.describe().contains(".locked"), "{}", b.describe());
}

/// MS-23, delete-originals variant: encrypted copies written as new files
/// (`f.locked`), then the originals deleted. The copy beside a deleted
/// original is found and is ciphertext.
#[test]
fn new_copies_then_deleted_originals_are_decisive() {
    let h = Host::new();
    h.exec(300, 200, "/usr/bin/python3", &["python3", SIM]);
    let (_dir, dir) = sandbox();
    let d = dir.to_str().unwrap().to_string();
    std::fs::write(dir.join("f017.locked"), b"ciphertext").unwrap();
    let t = h.tracker(Fixed::high(&d));
    let a = t
        .assess(&new_files(300, T0, &format!("{d}/f003.locked")))
        .unwrap();
    assert!(!a.decisive && a.added.is_empty());
    let b = t
        .assess(&unlinks(300, T0 + 2 * S, &format!("{d}/f017")))
        .unwrap();
    assert!(b.decisive, "{b:?}");
    let shapes: Vec<Signal> = b.signals.iter().map(|(s, _)| *s).collect();
    assert_eq!(
        shapes,
        vec![
            Signal::Entropy,
            Signal::RenameExtension,
            Signal::DeleteOriginals
        ]
    );
}

/// A backup or a rotation by a script: copies of plain content, then the
/// originals deleted — one shape (the deletion).
#[test]
fn plain_copies_and_deletions_are_one_shape() {
    let h = Host::new();
    h.exec(300, 200, "/usr/bin/bash", &["bash", "/home/u/archive.sh"]);
    let (_dir, dir) = sandbox();
    let d = dir.to_str().unwrap().to_string();
    std::fs::write(dir.join("app.log.old"), b"plain").unwrap();
    let t = h.tracker(Fixed::low());
    t.assess(&new_files(300, T0, &format!("{d}/x.old")))
        .unwrap();
    let b = t
        .assess(&unlinks(300, T0 + S, &format!("{d}/app.log")))
        .unwrap();
    assert!(!b.decisive, "{b:?}");
    assert_eq!(b.added, vec![Signal::DeleteOriginals]);
    // An unlink burst with no new files written first is no shape at all
    // (`rm -rf`, a cache sweep).
    h.exec(310, 200, "/home/u/cleaner", &["cleaner"]);
    let c = t.assess(&unlinks(310, T0, "/home/u/.cache/x")).unwrap();
    assert!(c.added.is_empty() && !c.decisive);
}

/// The legitimate bulk tools, packaged and started by a person: never
/// counted, whatever they do.
#[test]
fn packaged_bulk_tools_never_count() {
    let h = Host::new();
    h.exec(400, 200, "/usr/bin/tar", &["tar", "xf", "big.tar"]);
    h.exec(
        401,
        200,
        "/usr/bin/rsync",
        &["rsync", "-a", "--inplace", "a/", "b/"],
    );
    h.exec(402, 200, "/usr/bin/git", &["git", "checkout", "main"]);
    let t = h.tracker(Fixed::high("/"));
    for pid in [400, 401, 402] {
        for (i, e) in [
            rewrites(pid, T0, "/srv/data/x"),
            new_files(pid, T0 + S, "/srv/data/y.bin"),
            renames(pid, T0 + 2 * S, "/srv/data/x.old", 20, 5),
            unlinks(pid, T0 + 3 * S, "/srv/data/z"),
        ]
        .iter()
        .enumerate()
        {
            let a = t.assess(e).unwrap();
            assert!(a.trusted.is_some(), "{pid}/{i}: {a:?}");
            assert!(!a.decisive && a.added.is_empty());
        }
    }
    assert_eq!(t.counts().decisive, 0);
    assert_eq!(t.counts().trusted, 12);
}

/// The same tools started by a script from a home directory are judged:
/// one tool showing two shapes is decisive and the kill targets the
/// script; two tools showing one each are two bursts, not one.
#[test]
fn a_scripts_tools_are_judged_one_by_one_and_the_script_is_the_target() {
    let h = Host::new();
    h.exec(300, 200, "/usr/bin/bash", &["bash", "/home/u/enc.sh"]);
    h.exec(400, 300, "/usr/bin/tar", &["tar", "xf", "x.tar"]);
    h.exec(401, 300, "/usr/bin/mv", &["mv", "a", "a.locked"]);
    let t = h.tracker(Fixed::low());
    let a = t.assess(&rewrites(400, T0, "/srv/data/a")).unwrap();
    assert_eq!(
        (a.actor, a.key, a.program.as_str()),
        (300, 400, "/home/u/enc.sh")
    );
    assert!(!a.decisive);
    let b = t
        .assess(&renames(401, T0 + S, "/srv/data/a.locked", 20, 0))
        .unwrap();
    assert!(!b.decisive, "two tools, one shape each: {b:?}");
    let c = t
        .assess(&renames(400, T0 + 2 * S, "/srv/data/b.locked", 20, 0))
        .unwrap();
    assert!(c.decisive, "{c:?}");
    assert_eq!(c.actor, 300, "the kill targets the script");
}

/// A rename burst that is no encryptor's shape: one kind of original,
/// extension replaced (`.jpeg` → `.jpg`). Not a shape; the list's
/// extensions always are.
#[test]
fn rename_shapes() {
    let h = Host::new();
    h.exec(300, 200, "/home/u/bin/convert", &["convert"]);
    let t = h.tracker(Fixed::low());
    let a = t
        .assess(&renames(300, T0, "/home/u/pics/x.jpg", 0, 0))
        .unwrap();
    assert!(!a.rename_burst && a.added.is_empty());
    let b = t
        .assess(&renames(300, T0 + S, "/home/u/pics/x.crypted", 0, 0))
        .unwrap();
    assert!(b.rename_burst, "a listed extension is a shape");
    let c = t
        .assess(&renames(300, T0 + 2 * S, "/home/u/pics/x.zz", 0, 7))
        .unwrap();
    assert!(c.rename_burst, "originals of many kinds");
}

/// Shapes further apart than the window do not combine.
#[test]
fn shapes_outside_the_window_do_not_combine() {
    let h = Host::new();
    h.exec(300, 200, "/usr/bin/python3", &["python3", SIM]);
    let t = h.tracker(Fixed::low());
    t.assess(&rewrites(300, T0, "/srv/nn-malsim/a")).unwrap();
    let b = t
        .assess(&renames(
            300,
            T0 + RANSOM_WINDOW_NS + S,
            "/srv/nn-malsim/a.locked",
            20,
            0,
        ))
        .unwrap();
    assert!(!b.decisive, "{b:?}");
}

/// The posture and the rule engine read one event: one assessment, one
/// sampling.
#[test]
fn one_event_is_assessed_once() {
    let h = Host::new();
    h.exec(300, 200, "/usr/bin/python3", &["python3", SIM]);
    let sampler = Fixed::high("/srv/");
    let t = h.tracker(Arc::clone(&sampler));
    let e = rewrites(300, T0, "/srv/nn-malsim/f020");
    let a = t.assess(&e).unwrap();
    let b = t.assess(&e).unwrap();
    assert!(Arc::ptr_eq(&a, &b));
    assert_eq!(sampler.calls.load(Ordering::Relaxed), 1);
    assert_eq!(t.counts().decisive, 1);
    assert!(t
        .assess(&Event::Fim(nn_model::telemetry::FimEvent {
            timestamp_ns: 0,
            path: "/x".into(),
            op: nn_model::telemetry::FimOp::Modified,
            new_sha256: None,
            baseline_sha256: None,
            new_size: None,
            baseline_size: None,
            modifier_exe: None,
            modifier_pid: 1,
            modifier_uid: 0,
            modifier_comm: String::new(),
            dest_path: None,
            child_truncated: false,
            wide_coverage: false,
            owner_uid: None,
            reader_dac_capable: false,
            capability: None,
            attrs: None,
            file_key: None,
            is_dir: false,
            moved_in: false,
        }))
        .is_none());
}
