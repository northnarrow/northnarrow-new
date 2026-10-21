//! Lab PR 225: the ransomware tracker — two shapes of one actor are
//! decisive, one is not, trusted writers never count.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::{Event, FileBurstKind};
use parking_lot::Mutex;
use tempfile::TempDir;

use super::entropy::{Sample, Sampler};
use super::trust::ProgramOwners;
use super::*;

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
    let dir = TempDir::new().unwrap();
    let d = dir.path().to_str().unwrap().to_string();
    std::fs::write(dir.path().join("f017.locked"), b"ciphertext").unwrap();
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
    let dir = TempDir::new().unwrap();
    let d = dir.path().to_str().unwrap().to_string();
    std::fs::write(dir.path().join("app.log.old"), b"plain").unwrap();
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
        .assess(&Event::Fim(common::wire::FimEvent {
            timestamp_ns: 0,
            path: "/x".into(),
            op: common::wire::FimOp::Modified,
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

// --- Copy-delete on real files, through the production sampler --------
//
// Lab MS-23 copy-delete (debian12): the unlink crossing came at the 20th
// original, 280 originals written a minute before still beside the 20
// copies. The sampler read "the files beside the copy changed in the
// window" — those originals — one of four sampled as ciphertext, and
// NN-L-IMP-001 never fired. The tests above give the tracker a sampler
// with fixed answers; these read the files.

/// Bytes that look like ciphertext: xorshift output with no format
/// signature at the start.
fn cipher(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    let mut b: Vec<u8> = (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect();
    b[0] = 0x42;
    b
}

/// `head` followed by ciphertext-like bytes: a container (gzip, ELF, …).
fn container(head: &[u8], n: usize, seed: u64) -> Vec<u8> {
    let mut b = cipher(n, seed);
    b[..head.len()].copy_from_slice(head);
    b
}

/// Plain text, the simulator's originals.
fn plain(n: usize) -> Vec<u8> {
    let mut b = b"nn-ms plain document\n".to_vec();
    while b.len() < n {
        b.extend_from_slice(b"Quarterly figures, plain text that compresses well. \n");
    }
    b.truncate(n);
    b
}

/// The tracker over `h` with the production sampler.
fn fs_tracker(h: &Host) -> RansomTracker {
    RansomTracker::with(
        h.lineage.clone(),
        ProgramOwners::new(h.root.path()),
        Arc::new(super::entropy::FsSampler),
    )
}

/// The simulator's tree: `n` plain originals of 8 KiB in `dir`, the first
/// `done` of them encrypted into `<name>.locked` and deleted. Returns the
/// last original deleted.
fn copy_delete(dir: &std::path::Path, n: usize, done: usize) -> String {
    let kinds = ["docx", "pdf", "xlsx", "txt", "csv", "odt", "jpg"];
    let mut last = String::new();
    for i in 0..n {
        let p = dir.join(format!("report-{i:04}.{}", kinds[i % kinds.len()]));
        std::fs::write(&p, plain(8192)).unwrap();
    }
    for i in 0..done {
        let p = dir.join(format!("report-{i:04}.{}", kinds[i % kinds.len()]));
        let mut c = p.clone().into_os_string();
        c.push(".locked");
        std::fs::write(&c, cipher(8192, i as u64 + 1)).unwrap();
        std::fs::remove_file(&p).unwrap();
        last = p.to_str().unwrap().to_string();
    }
    last
}

fn shapes_of(a: &Assessment) -> Vec<Signal> {
    a.signals.iter().map(|(s, _)| *s).collect()
}

/// MS-23 copy-delete as the lab ran it: 20 copies, 280 originals still
/// waiting beside them. The copies are what is sampled: decisive at the
/// unlink crossing, with the deletions, the copies' names and their
/// content — the evidence standard of the in-place run (two shapes).
#[test]
fn copy_delete_beside_fresh_originals_is_decisive() {
    let h = Host::new();
    h.exec(300, 200, "/usr/bin/python3", &["python3", SIM]);
    let dir = TempDir::new().unwrap();
    let deleted = copy_delete(dir.path(), 300, 20);
    let t = fs_tracker(&h);
    let a = t
        .assess(&new_files(300, T0, &format!("{deleted}.locked")))
        .unwrap();
    assert!(!a.decisive && a.added.is_empty(), "{a:?}");
    let b = t.assess(&unlinks(300, T0 + S, &deleted)).unwrap();
    assert!(b.decisive, "{b:?}");
    assert_eq!(
        shapes_of(&b),
        vec![
            Signal::Entropy,
            Signal::RenameExtension,
            Signal::DeleteOriginals
        ]
    );
    assert!(
        b.describe().contains("4 of 4 copies under .locked"),
        "{}",
        b.describe()
    );
    assert_eq!(b.actor, 300);
    assert_eq!(t.counts().decisive, 1);
}

/// An encryptor walking a tree of small directories: one original per
/// directory, so the deleted file's directory holds one copy. The copies
/// beside it (the parent's other directories) are sampled.
#[test]
fn copy_delete_in_a_tree_of_small_directories_is_decisive() {
    let h = Host::new();
    h.exec(300, 200, "/home/u/.cache/x/enc", &["enc"]);
    let root = TempDir::new().unwrap();
    let mut deleted = String::new();
    for i in 0..25 {
        let d = root.path().join(format!("project-{i:02}"));
        std::fs::create_dir(&d).unwrap();
        let p = d.join("notes.odt");
        std::fs::write(&p, plain(6000)).unwrap();
        if i < 20 {
            std::fs::write(d.join("notes.odt.crypt"), cipher(6000, i + 7)).unwrap();
            std::fs::remove_file(&p).unwrap();
            deleted = p.to_str().unwrap().to_string();
        }
    }
    let t = fs_tracker(&h);
    t.assess(&new_files(300, T0, &format!("{deleted}.crypt")))
        .unwrap();
    let b = t.assess(&unlinks(300, T0 + S, &deleted)).unwrap();
    assert!(b.decisive, "{b:?}");
    assert!(
        b.describe().contains("copies under .crypt"),
        "{}",
        b.describe()
    );
}

/// The burst's crossing write-open was a ransom note, not a copy: the
/// copy beside the deleted original is found by its name all the same,
/// whatever its appended extension.
#[test]
fn copy_delete_whose_crossing_write_was_a_ransom_note_is_decisive() {
    let h = Host::new();
    h.exec(300, 200, "/usr/bin/python3", &["python3", SIM]);
    let dir = TempDir::new().unwrap();
    let kinds = ["docx", "pdf", "xlsx"];
    let mut deleted = String::new();
    for i in 0..40 {
        let p = dir.path().join(format!("f{i:03}.{}", kinds[i % 3]));
        std::fs::write(&p, plain(5000)).unwrap();
        if i < 20 {
            let c = format!(
                "{}.id-7F3A.[restore@example.invalid].wallet",
                p.to_str().unwrap()
            );
            std::fs::write(&c, cipher(5000, i as u64 + 3)).unwrap();
            std::fs::remove_file(&p).unwrap();
            deleted = p.to_str().unwrap().to_string();
        }
    }
    let note = dir.path().join("HOW_TO_RESTORE.txt");
    std::fs::write(&note, b"your files are encrypted (lab text)").unwrap();
    let t = fs_tracker(&h);
    t.assess(&new_files(300, T0, note.to_str().unwrap()))
        .unwrap();
    let b = t.assess(&unlinks(300, T0 + S, &deleted)).unwrap();
    assert!(b.decisive, "{b:?}");
    assert!(
        b.describe()
            .contains(".id-7F3A.[restore@example.invalid].wallet"),
        "{}",
        b.describe()
    );
}

/// Legitimate copy-then-delete shapes, each run by a program no package
/// vouches for (a user's script or a tool from a home directory — the
/// packaged ones are trusted before any shape is read): new files written,
/// 20 originals of 4 KiB or more deleted, the worst case of content where
/// it matters. One shape at most (the deletion), never decisive.
#[test]
fn benign_copy_delete_shapes_are_not_decisive() {
    let h = Host::new();
    let t = fs_tracker(&h);
    let mut pid = 500;
    let mut run = |label: &str, prog: &str, new_file: &str, deleted: &str| {
        pid += 1;
        h.exec(pid, 200, "/usr/bin/bash", &["bash", prog]);
        t.assess(&new_files(pid, T0, new_file)).unwrap();
        let b = t.assess(&unlinks(pid, T0 + S, deleted)).unwrap();
        assert!(!b.decisive, "{label}: {b:?}");
        assert!(
            b.added.iter().all(|s| *s == Signal::DeleteOriginals),
            "{label}: {b:?}"
        );
    };
    let p = |d: &TempDir, rel: &str| d.path().join(rel).to_str().unwrap().to_string();

    // `mv` across filesystems: the copy keeps its name in another tree,
    // then the original goes (random content: the worst case).
    let src = TempDir::new().unwrap();
    let dst = TempDir::new().unwrap();
    for i in 0..20 {
        std::fs::write(dst.path().join(format!("f{i:02}.bin")), cipher(8192, i)).unwrap();
    }
    for i in 20..40 {
        std::fs::write(src.path().join(format!("f{i:02}.bin")), cipher(8192, i)).unwrap();
    }
    run(
        "mv across filesystems",
        "/home/u/move.sh",
        &p(&dst, "f19.bin"),
        &p(&src, "f19.bin"),
    );

    // `rsync --remove-source-files`: a temporary `.name.XXXXXX` renamed to
    // the name in the destination, then the source removed.
    let src = TempDir::new().unwrap();
    let dst = TempDir::new().unwrap();
    for i in 0..20 {
        std::fs::write(dst.path().join(format!("f{i:02}.bin")), cipher(8192, i)).unwrap();
        std::fs::write(src.path().join(format!("g{i:02}.bin")), cipher(8192, i)).unwrap();
    }
    run(
        "rsync --remove-source-files",
        "/home/u/sync.sh",
        &p(&dst, ".f19.bin.Xy12Ab"),
        &p(&src, "f19.bin"),
    );

    // A package manager's unpack: `x.dpkg-new` written beside `x`, the old
    // file removed, the new one renamed over it — the copy beside the
    // deleted file is a shared object (ELF), not ciphertext.
    let lib = TempDir::new().unwrap();
    for i in 0..20 {
        std::fs::write(
            lib.path().join(format!("libx{i}.so.dpkg-new")),
            container(b"\x7fELF", 16384, i + 40),
        )
        .unwrap();
    }
    run(
        "package unpack",
        "/home/u/pkg/install.sh",
        &p(&lib, "libx19.so.dpkg-new"),
        &p(&lib, "libx19.so"),
    );

    // A compiler: assembly written then deleted, objects written then
    // deleted once linked.
    let tmp = TempDir::new().unwrap();
    for i in 0..20 {
        std::fs::write(
            tmp.path().join(format!("cc{i:02}.o")),
            container(b"\x7fELF", 8192, i),
        )
        .unwrap();
    }
    run(
        "compiler temporaries",
        "/home/u/src/build.sh",
        &p(&tmp, "cc19.o"),
        &p(&tmp, "cc19.s"),
    );

    // An editor's safe write: `x.tmp` written beside `x`, `x` removed, the
    // temporary renamed — the copy beside is the edited text.
    let docs = TempDir::new().unwrap();
    for i in 0..20 {
        std::fs::write(docs.path().join(format!("notes{i:02}.md.tmp")), plain(6000)).unwrap();
    }
    run(
        "editor temporary then unlink",
        "/home/u/.local/editor/run.sh",
        &p(&docs, "notes19.md.tmp"),
        &p(&docs, "notes19.md"),
    );

    // `git gc`: packs written (`PACK` is no known signature: random
    // bytes after it), loose objects deleted — no copy beside an object.
    let git = TempDir::new().unwrap();
    std::fs::create_dir_all(git.path().join("objects/pack")).unwrap();
    std::fs::create_dir_all(git.path().join("objects/3f")).unwrap();
    std::fs::write(
        git.path().join("objects/pack/pack-0c1d.pack"),
        container(b"PACK\0\0\0\x02", 65536, 77),
    )
    .unwrap();
    std::fs::write(
        git.path().join("objects/pack/pack-0c1d.idx"),
        container(b"\xfftOc", 8192, 78),
    )
    .unwrap();
    run(
        "git gc",
        "/home/u/.local/bin/git-maint.sh",
        &p(&git, "objects/pack/pack-0c1d.pack"),
        &p(&git, "objects/3f/a9c8ea553e6afa8874057e6eb59b0ebf264eb2"),
    );

    // Log rotation with compression: `app.log.1.gz` written, `app.log.1`
    // removed — the copy beside is compressed (gzip, zstd), a container.
    for (ext, head) in [("gz", &b"\x1f\x8b"[..]), ("zst", &b"\x28\xb5\x2f\xfd"[..])] {
        let logs = TempDir::new().unwrap();
        for i in 0..20 {
            std::fs::write(
                logs.path().join(format!("app{i:02}.log.1.{ext}")),
                container(head, 8192, i + 9),
            )
            .unwrap();
        }
        run(
            "log rotation with compression",
            "/home/u/rotate.sh",
            &p(&logs, &format!("app19.log.1.{ext}")),
            &p(&logs, "app19.log.1"),
        );
    }
    assert_eq!(t.counts().decisive, 0);
}
