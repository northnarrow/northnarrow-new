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
        small_files: false,
        cgroup_id: 0,
        own_data: 0,
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
        small_files: false,
        cgroup_id: 0,
        own_data: 0,
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
        cgroup_id: 0,
        own_data: 0,
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
        cgroup_id: 0,
        own_data: 0,
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

/// The re-review of #500 (B1's residual, its probe
/// `review500_rr_presized_copies_then_deleted_originals`): the copies made
/// first (`mknod`, or `O_RDONLY | O_CREAT`), brought to one byte by
/// `truncate(2)` — no open — then written: the kernel counts them as small
/// rewrites (`MassWrite { overwrites: true, small_files: true }`), not as
/// files written new. They are files the actor wrote all the same: with
/// the originals deleted beside them, the copies of their shape and their
/// content, decisive as `new_copies_then_deleted_originals_are_decisive` —
/// as on `main`, where every write-open counted.
#[test]
fn presized_copies_then_deleted_originals_are_decisive() {
    let h = Host::new();
    h.exec(300, 200, "/usr/bin/python3", &["python3", SIM]);
    let (_dir, dir) = sandbox();
    let d = dir.to_str().unwrap().to_string();
    std::fs::write(dir.join("f017.locked"), b"ciphertext").unwrap();
    let t = h.tracker(Fixed::high(&d));
    let mut presized = rewrites(300, T0, &format!("{d}/f003.locked"));
    if let Event::MassWrite { small_files, .. } = &mut presized {
        *small_files = true;
    }
    let a = t.assess(&presized).unwrap();
    assert!(!a.decisive && a.added.is_empty(), "{a:?}");
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
    // the files of 4 KiB or more rewritten are shape (a), never files
    // written for (d)
    let h = Host::new();
    h.exec(301, 200, "/usr/bin/python3", &["python3", SIM]);
    let t = h.tracker(Fixed::low());
    let _ = t.assess(&rewrites(301, T0, &format!("{d}/g003"))).unwrap();
    let c = t
        .assess(&unlinks(301, T0 + 2 * S, &format!("{d}/f017")))
        .unwrap();
    assert!(
        !c.signals.iter().any(|(s, _)| *s == Signal::DeleteOriginals),
        "{c:?}"
    );
}

/// Lot 282, the review of #500 (C1): a crossing that needed files under
/// 4 KiB (`small_files`) is no shape (a) — a build rewrites its own small
/// outputs, and the tracker's verdict is decisive. The posture's arm reads
/// it (outside a session); the tracker sees small files encrypted in place
/// by their renames (c) and their entropy (b).
#[test]
fn a_crossing_of_small_files_is_no_rewrite_shape() {
    let h = Host::new();
    h.exec(300, 200, "/usr/bin/python3", &["python3", SIM]);
    let t = h.tracker(Fixed::high("/srv/nn-malsim/"));
    let mut e = rewrites(300, T0, "/srv/nn-malsim/f020");
    if let Event::MassWrite { small_files, .. } = &mut e {
        *small_files = true;
    }
    let a = t.assess(&e).unwrap();
    assert!(!a.decisive, "{a:?}");
    assert!(a.signals.is_empty(), "{a:?}");
    assert_eq!(t.counts().decisive, 0);
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

/// External bug hunt BUG54 (documentation): the kernel counts an atomic
/// save whose temporary carries its own extension (`data.tmp` →
/// `data.json`: replaced, nothing appended) — the shape of an encryptor's
/// staging, so it stays counted — and a burst of them is no encryptor's
/// shape here: one origin extension, no append, `.json` no marker. No
/// signal, no verdict, as RANSOMWARE_DECISIVE.md now says.
#[test]
fn an_atomic_save_burst_replacing_the_extension_is_not_shaped() {
    let h = Host::new();
    h.exec(300, 200, "/home/u/bin/editor", &["editor"]);
    let t = h.tracker(Fixed::high("/home/u/proj/"));
    let a = t
        .assess(&renames(300, T0, "/home/u/proj/data.json", 0, 0))
        .unwrap();
    assert!(
        !a.rename_burst && a.added.is_empty() && !a.decisive,
        "{a:?}"
    );
    // the staged ciphertext of the same shape under a marker is one
    let b = t
        .assess(&renames(300, T0 + S, "/home/u/proj/data.locked", 0, 0))
        .unwrap();
    assert!(b.rename_burst, "a listed marker extension is a shape");
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

/// Lot 283c, decision 5: NN-L-IMP-001 judges a service account that
/// encrypts its own data exactly as it judges anyone — the kernel's
/// own-data summary (`own_data`, which only the posture's mass-write arm
/// reads) changes nothing. A payload the PostgreSQL account runs from its
/// service, rewriting the account's own files into ciphertext, is decisive
/// in place, and so are its copies with the originals deleted.
#[test]
fn imp001_still_judges_a_service_encrypting_its_own_data() {
    use common::wire::open_sensor::own_data;
    let own = |mut e: Event| {
        match &mut e {
            Event::MassWrite {
                uid, own_data: o, ..
            }
            | Event::FileBurst {
                uid, own_data: o, ..
            } => (*uid, *o) = (113, own_data::SERVICE),
            _ => unreachable!(),
        }
        e
    };
    let payload = "/var/lib/postgresql/.cache/enc";
    for marked in [false, true] {
        let h = Host::new();
        h.lineage
            .ingest_exec(400, 1, payload, &["enc".into()], 10 * S, 10 * S, 113);
        let (_dir, dir) = sandbox();
        let d = dir.to_str().unwrap().to_string();
        let t = h.tracker(Fixed::high(&d));
        let mark = |e: Event| if marked { own(e) } else { e };
        // in place: the rewrites, ciphertext left behind
        let a = t
            .assess(&mark(rewrites(400, T0, &format!("{d}/base/16384/2833"))))
            .unwrap();
        assert!(a.decisive, "marked {marked}: {a:?}");
        assert!(a.trusted.is_none(), "{a:?}");
        assert_eq!(a.program, payload);
        // copies, then the originals deleted
        let h = Host::new();
        h.lineage
            .ingest_exec(401, 1, payload, &["enc".into()], 10 * S, 10 * S, 113);
        std::fs::write(dir.join("f017.locked"), b"ciphertext").unwrap();
        let t = h.tracker(Fixed::high(&d));
        let first = t
            .assess(&mark(new_files(401, T0, &format!("{d}/f003.locked"))))
            .unwrap();
        assert!(!first.decisive);
        let b = t
            .assess(&mark(unlinks(401, T0 + 2 * S, &format!("{d}/f017"))))
            .unwrap();
        assert!(b.decisive, "marked {marked}: {b:?}");
    }
}

// ── Lot 292 (external bug hunt, editions 1.2/1.3): BUG-72 ──────────────

/// BUG-72: the same actor (pid 500, `/tmp/x`) rewrites at t0; 30 s later its
/// lineage cannot be read any more (its parent's pid now names a process
/// that started before t1 and executed after it: what that pid ran then is
/// not known) and it renames to a new extension. The walk fails toward
/// counting ("(lineage unknown)", same key), and the shape counted 30 s
/// earlier is still in the window.
#[test]
fn unreadable_lineage_mid_window_keeps_the_actors_shapes() {
    let h = Host::new();
    h.exec(500, 200, "/tmp/x", &["x"]);
    let t = h.tracker(Fixed::low());
    let t1 = T0 + 30 * S;
    let a1 = t.assess(&rewrites(500, T0, "/home/u/docs/a.pdf")).unwrap();
    assert_eq!((a1.program.as_str(), a1.key), ("/tmp/x", 500));
    assert_eq!(a1.added, vec![Signal::Rewrites]);
    h.lineage.ingest_exec(
        200,
        1,
        "/usr/bin/true",
        &["true".to_string()],
        t1 + 10 * S,
        T0 + S,
        1000,
    );
    let a2 = t
        .assess(&renames(500, t1, "/home/u/docs/a.pdf.locked", 20, 3))
        .unwrap();
    // preconditions: unreadable, still judged under the same key
    assert_eq!((a2.program.as_str(), a2.key), ("(lineage unknown)", 500));
    assert_eq!(a2.added, vec![Signal::RenameExtension]);
    let shapes: Vec<Signal> = a2.signals.iter().map(|(s, _)| *s).collect();
    assert!(
        shapes.contains(&Signal::Rewrites) && a2.decisive,
        "the rewrites counted 30 s earlier for pid 500 were dropped: {shapes:?}, decisive {}",
        a2.decisive
    );
}

/// BUG-72, the other way: the window opened while the lineage could not be
/// read ("(lineage unknown)") is the actor's once its program is read
/// again; and two programs read under one pid (a pid reused) still start
/// the window over.
#[test]
fn a_window_opened_unreadable_is_the_actor_s_once_read() {
    let h = Host::new();
    let t = h.tracker(Fixed::low());
    // no exec of pid 510 known yet: not readable
    let a1 = t.assess(&rewrites(510, T0, "/home/u/docs/b.pdf")).unwrap();
    assert_eq!((a1.program.as_str(), a1.key), ("(lineage unknown)", 510));
    h.exec(510, 1, "/tmp/y", &["y"]);
    let a2 = t
        .assess(&renames(
            510,
            T0 + 30 * S,
            "/home/u/docs/b.pdf.locked",
            20,
            3,
        ))
        .unwrap();
    assert_eq!((a2.program.as_str(), a2.key), ("/tmp/y", 510));
    let shapes: Vec<Signal> = a2.signals.iter().map(|(s, _)| *s).collect();
    assert!(
        shapes.contains(&Signal::Rewrites) && a2.decisive,
        "{shapes:?}"
    );
    // pid 520 runs /tmp/a, then (reused) /tmp/b: two programs, two windows
    h.exec(520, 1, "/tmp/a", &["a"]);
    let b1 = t.assess(&rewrites(520, T0, "/home/u/docs/c.pdf")).unwrap();
    assert_eq!(b1.program, "/tmp/a");
    // a later process takes the pid and executes /tmp/b
    h.lineage.ingest_exec(
        520,
        1,
        "/tmp/b",
        &["b".to_string()],
        T0 + 10 * S,
        T0 + 5 * S,
        1000,
    );
    let b2 = t
        .assess(&renames(
            520,
            T0 + 30 * S,
            "/home/u/docs/c.pdf.locked",
            20,
            3,
        ))
        .unwrap();
    assert_eq!(b2.program, "/tmp/b");
    let shapes: Vec<Signal> = b2.signals.iter().map(|(s, _)| *s).collect();
    assert_eq!(
        shapes,
        vec![Signal::RenameExtension],
        "a reused pid's shapes"
    );
    assert!(!b2.decisive);
}
