//! Lab PR 225 (the ransomware tracker): copy-delete on real files, through
//! the production sampler of the host's files.
//!
//! R08b (lab PR 251): cut verbatim from `impact`'s tests when the tracker
//! moved to nn-core: they read real files through the agent's sampler
//! ([`super::entropy::FsSampler`]: the owners, the mode bits, `O_NOFOLLOW`),
//! the agent's host's. The fixtures they share with the tracker's other
//! tests (nn-core's) are copied with them.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use nn_model::{Event, FileBurstKind};
use tempfile::TempDir;

use super::trust::ProgramOwners;
use super::*;
use crate::posture::lineage::AuthSessionTracker;

const S: u64 = 1_000_000_000;
const T0: u64 = 1_000 * S;

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
    let (_dir, dir) = sandbox();
    let deleted = copy_delete(&dir, 300, 20);
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
    let (_root, root) = sandbox();
    let mut deleted = String::new();
    for i in 0..25 {
        let d = root.join(format!("project-{i:02}"));
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
    let (_dir, dir) = sandbox();
    let kinds = ["docx", "pdf", "xlsx"];
    let mut deleted = String::new();
    for i in 0..40 {
        let p = dir.join(format!("f{i:03}.{}", kinds[i % 3]));
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
    let note = dir.join("HOW_TO_RESTORE.txt");
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
    let p = |d: &Path, rel: &str| d.join(rel).to_str().unwrap().to_string();

    // `mv` across filesystems: the copy keeps its name in another tree,
    // then the original goes (random content: the worst case).
    let (_src, src) = sandbox();
    let (_dst, dst) = sandbox();
    for i in 0..20 {
        std::fs::write(dst.join(format!("f{i:02}.bin")), cipher(8192, i)).unwrap();
    }
    for i in 20..40 {
        std::fs::write(src.join(format!("f{i:02}.bin")), cipher(8192, i)).unwrap();
    }
    run(
        "mv across filesystems",
        "/home/u/move.sh",
        &p(&dst, "f19.bin"),
        &p(&src, "f19.bin"),
    );

    // `rsync --remove-source-files`: a temporary `.name.XXXXXX` renamed to
    // the name in the destination, then the source removed.
    let (_src, src) = sandbox();
    let (_dst, dst) = sandbox();
    for i in 0..20 {
        std::fs::write(dst.join(format!("f{i:02}.bin")), cipher(8192, i)).unwrap();
        std::fs::write(src.join(format!("g{i:02}.bin")), cipher(8192, i)).unwrap();
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
    let (_lib, lib) = sandbox();
    for i in 0..20 {
        std::fs::write(
            lib.join(format!("libx{i}.so.dpkg-new")),
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
    let (_tmp, tmp) = sandbox();
    for i in 0..20 {
        std::fs::write(
            tmp.join(format!("cc{i:02}.o")),
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
    let (_docs, docs) = sandbox();
    for i in 0..20 {
        std::fs::write(docs.join(format!("notes{i:02}.md.tmp")), plain(6000)).unwrap();
    }
    run(
        "editor temporary then unlink",
        "/home/u/.local/editor/run.sh",
        &p(&docs, "notes19.md.tmp"),
        &p(&docs, "notes19.md"),
    );

    // `git gc`: packs written (`PACK` is no known signature: random
    // bytes after it), loose objects deleted — no copy beside an object.
    let (_git, git) = sandbox();
    std::fs::create_dir_all(git.join("objects/pack")).unwrap();
    std::fs::create_dir_all(git.join("objects/3f")).unwrap();
    std::fs::write(
        git.join("objects/pack/pack-0c1d.pack"),
        container(b"PACK\0\0\0\x02", 65536, 77),
    )
    .unwrap();
    std::fs::write(
        git.join("objects/pack/pack-0c1d.idx"),
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
        let (_logs, logs) = sandbox();
        for i in 0..20 {
            std::fs::write(
                logs.join(format!("app{i:02}.log.1.{ext}")),
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

/// A job of a user's script in a directory of its own under a shared
/// temporary directory (world-writable, sticky: `/tmp`): its copy-then-
/// delete leaves one plain copy beside the original it deleted, and
/// another tree of that directory — another user's, another program's —
/// holds fresh copies of ciphertext under the same suffix whose originals
/// are gone. Those are not this burst's evidence (and anyone can plant
/// them): one shape, the deletion, never decisive.
#[test]
fn another_tree_of_a_shared_directory_is_no_evidence() {
    use std::os::unix::fs::PermissionsExt;
    let h = Host::new();
    h.exec(300, 200, "/usr/bin/bash", &["bash", "/home/u/etl.sh"]);
    let (_w, w) = sandbox();
    let tmp = w.join("tmp");
    let job = tmp.join("etl-4711");
    let other = tmp.join("u2-export");
    std::fs::create_dir_all(&job).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(job.join("orders.csv.part"), plain(8192)).unwrap();
    for i in 0..6 {
        std::fs::write(
            other.join(format!("blob{i}.bin.part")),
            cipher(8192, i + 90),
        )
        .unwrap();
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o1777)).unwrap();
    let deleted = job.join("orders.csv").to_str().unwrap().to_string();
    let t = fs_tracker(&h);
    t.assess(&new_files(300, T0, &format!("{deleted}.part")))
        .unwrap();
    let b = t.assess(&unlinks(300, T0 + S, &deleted)).unwrap();
    assert!(!b.decisive, "{b:?}");
    assert_eq!(b.added, vec![Signal::DeleteOriginals], "{b:?}");
    assert_eq!(t.counts().samplings, 1);
}

/// An unlink burst run as `uid`.
fn unlinks_by(uid: u32, pid: u32, ts: u64, file: &str) -> Event {
    match unlinks(pid, ts, file) {
        Event::FileBurst {
            pid,
            comm,
            kind,
            count,
            appended,
            sources,
            filename,
            timestamp_ns,
            ..
        } => Event::FileBurst {
            pid,
            uid,
            comm,
            kind,
            count,
            appended,
            sources,
            filename,
            timestamp_ns,
        },
        e => e,
    }
}

/// Lab PR 238: the burst's own directory is a shared one (`/tmp` itself,
/// world-writable and sticky). Its copies count when the uid the burst ran
/// as owns them — an encryptor's copies are new files, its own: the
/// simulator's run there is decisive as anywhere. Run as another uid, the
/// same copies are another user's, no evidence of this burst: one shape,
/// the deletion.
#[test]
fn copy_delete_in_a_shared_directory_counts_the_bursts_own_copies() {
    use std::os::unix::fs::PermissionsExt;
    // SAFETY: geteuid(2) has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    let h = Host::new();
    h.exec(300, 200, "/usr/bin/python3", &["python3", SIM]);
    let (_w, w) = sandbox();
    let tmp = w.join("tmp");
    std::fs::create_dir(&tmp).unwrap();
    let deleted = copy_delete(&tmp, 40, 20);
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o1777)).unwrap();

    let t = fs_tracker(&h);
    t.assess(&new_files(300, T0, &format!("{deleted}.locked")))
        .unwrap();
    let b = t.assess(&unlinks_by(me, 300, T0 + S, &deleted)).unwrap();
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

    let t = fs_tracker(&h);
    t.assess(&new_files(300, T0, &format!("{deleted}.locked")))
        .unwrap();
    let b = t
        .assess(&unlinks_by(me.wrapping_add(1), 300, T0 + S, &deleted))
        .unwrap();
    assert!(!b.decisive, "{b:?}");
    assert_eq!(b.added, vec![Signal::DeleteOriginals], "{b:?}");
    assert_eq!(t.counts().samplings, 1);
}
