//! Review of lab PR 222 (A.3): the copy-on-first-write guard on a scope
//! marked by mount, its journal under the mark (the default
//! `<scope>/.northnarrow-cow`). The guard's own opens of journal files are
//! permission events its fanotify reader must answer, and the reader takes
//! the journal's and the index's locks: a journal file opened with one of
//! those locks held made the guard wait on itself until the 3 s stall closed
//! its group (every open allowed, the guard off for the rest of the run).
//! No journal file is opened under those locks now; this test drives copies,
//! shared copies, index commits and compactions under `mark=mount` and
//! checks the reader never stalled.
//!
//! Needs root (fanotify `FAN_CLASS_CONTENT`, a tmpfs mount):
//! `sudo -E cargo test -p northnarrow-agent --features test-privileged
//! --test cow_privileged_e2e -- --ignored`.
#![cfg(feature = "test-privileged")]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use northnarrow_agent::cow::config::CowConfig;
use northnarrow_agent::cow::guard::Runtime;
use northnarrow_agent::cow::store::Store;
use northnarrow_agent::posture::lineage::AuthSessionTracker;

/// The tmpfs mount, lazily unmounted at the end.
struct Mount(PathBuf);

impl Drop for Mount {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg("-l").arg(&self.0).status();
    }
}

#[test]
#[ignore = "requires root (fanotify, a tmpfs mount); lab: nn-lab.sh test-ignored"]
fn a_mount_marked_guard_never_waits_on_its_own_journal() {
    let dir = tempfile::Builder::new()
        .prefix("nn-cow-mount")
        .tempdir()
        .unwrap();
    let scope = dir.path().join("scope");
    std::fs::create_dir(&scope).unwrap();
    let mounted = Command::new("mount")
        .args(["-t", "tmpfs", "-o", "size=256m", "nn-cow-test"])
        .arg(&scope)
        .status()
        .unwrap();
    assert!(mounted.success(), "mount a tmpfs at the scope (root?)");
    let _mount = Mount(scope.clone());
    for i in 0..40u8 {
        std::fs::write(scope.join(format!("f{i:02}.bin")), vec![i; 64 * 1024]).unwrap();
    }
    let cfg = CowConfig::parse(&format!(
        "enabled = true\nscope = {} mark=mount\n",
        scope.display()
    ))
    .unwrap();
    // No pin root: the test registers nothing in the installed agent's maps
    // (R11c, lab PR 264: given here, as the process-wide one was unset).
    let (store, problems) = Store::open(cfg, None);
    assert!(problems.is_empty(), "{problems:?}");
    let tracker = AuthSessionTracker::new(dir.path());
    let guard = Runtime::start(Arc::clone(&store), tracker).expect("the guard starts");

    // Compactions, back to back, while the writers run (each one creates
    // the new index file under the mark).
    let stop = Arc::new(AtomicBool::new(false));
    let compactor = {
        let (store, stop) = (Arc::clone(&store), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                store.compact_all();
                std::thread::sleep(Duration::from_millis(5));
            }
        })
    };
    // Two writers at once, three rounds over every file: first copies,
    // copies shared by a second writer of an unchanged file, and the index
    // worker's commits, which open each copy to hash it.
    let script = format!(
        "for r in 1 2 3; do for f in {}/f*.bin; do printf x >> \"$f\"; done; done",
        scope.display()
    );
    let writers: Vec<_> = (0..2)
        .map(|_| Command::new("sh").arg("-c").arg(&script).spawn().unwrap())
        .collect();
    for mut w in writers {
        assert!(w.wait().unwrap().success());
    }
    std::thread::sleep(Duration::from_millis(500));
    stop.store(true, Ordering::Relaxed);
    compactor.join().unwrap();

    let state = guard.state();
    let idle = guard.reader_idle_ms();
    let status = guard.status();
    guard.stop();
    assert!(
        !state.contains("stalled"),
        "the guard stalled on its own journal: {state}"
    );
    assert!(idle < 3_000, "the reader made no progress for {idle} ms");
    assert!(
        status.scopes.first().is_some_and(|s| s.objects > 0),
        "no copy was taken: {status:?}"
    );
}

/// The guard's copies of `scope`'s files by one writer (`sh`), committed:
/// waits until the index holds `want` entries.
fn write_all_and_wait(store: &Store, scope: &std::path::Path, want: usize) {
    let script = format!(
        "for f in {}/f*.bin; do printf y >> \"$f\"; done",
        scope.display()
    );
    let ok = Command::new("sh").arg("-c").arg(&script).status().unwrap();
    assert!(ok.success());
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let n = store.index.lock().entry_count(0);
        if n >= want {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{n} of {want} copies committed within 20 s"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Every entry of the index (sorted by id) and every copy file with its
/// bytes.
fn snapshot(
    store: &Store,
    journal: &std::path::Path,
) -> (
    Vec<northnarrow_agent::cow::index::Entry>,
    Vec<(String, Vec<u8>)>,
) {
    let entries: Vec<_> = store.index.lock().entries().cloned().collect();
    let mut objects: Vec<(String, Vec<u8>)> = std::fs::read_dir(journal.join("objects"))
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    objects.sort();
    (entries, objects)
}

/// Lot 297 (external bug hunt BUG64): the guard's real copies (fanotify on
/// a tmpfs scope) survive a restart whose index.jsonl ends in a line cut
/// inside a multi-byte character (a crash during an append): the replay
/// skips that line alone, no copy is deleted as an orphan, and a copy
/// taken after the restart is a line of its own (the cut line was ended
/// at the open), there at the start after.
#[test]
#[ignore = "requires root (fanotify, a tmpfs mount); lab: nn-lab.sh test-one cow_privileged_e2e"]
fn a_torn_index_line_keeps_the_guards_copies() {
    let dir = tempfile::Builder::new()
        .prefix("nn-cow-torn")
        .tempdir()
        .unwrap();
    let scope = dir.path().join("scope");
    std::fs::create_dir(&scope).unwrap();
    let mounted = Command::new("mount")
        .args(["-t", "tmpfs", "-o", "size=64m", "nn-cow-test"])
        .arg(&scope)
        .status()
        .unwrap();
    assert!(mounted.success(), "mount a tmpfs at the scope (root?)");
    let _mount = Mount(scope.clone());
    for i in 0..10u8 {
        std::fs::write(scope.join(format!("f{i:02}.bin")), vec![i; 16 * 1024]).unwrap();
    }
    let journal = scope.join(".northnarrow-cow");
    let cfg = CowConfig::parse(&format!(
        "enabled = true\nscope = {} mark=mount\n",
        scope.display()
    ))
    .unwrap();
    let tracker = || AuthSessionTracker::new(dir.path());

    // A first run: a copy of every file.
    let (store, problems) = Store::open(cfg.clone(), None);
    assert!(problems.is_empty(), "{problems:?}");
    let guard = Runtime::start(Arc::clone(&store), tracker()).expect("the guard starts");
    write_all_and_wait(&store, &scope, 10);
    guard.stop();
    drop(guard);
    let (entries, objects) = snapshot(&store, &journal);
    assert_eq!(entries.len(), 10);
    assert!(!objects.is_empty());
    drop(store);

    // The crash: index.jsonl ends in a cut line.
    let index = journal.join("index.jsonl");
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&index)
        .unwrap();
    std::io::Write::write_all(
        &mut f,
        b"{\"op\":\"entry\",\"entry\":{\"id\":99,\"object\":99,\"scope\":0,\"path\":\"/srv/Universit\xC3",
    )
    .unwrap();
    drop(f);

    // The restart: the copies and their entries as they were, one line
    // counted; then a second writer's copies.
    let (store, problems) = Store::open(cfg.clone(), None);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        problems[0].contains("1 unreadable line(s) of index.jsonl skipped"),
        "{problems:?}"
    );
    assert_eq!(
        snapshot(&store, &journal),
        (entries.clone(), objects),
        "the restart kept every copy and entry"
    );
    let guard = Runtime::start(Arc::clone(&store), tracker()).expect("the guard starts");
    write_all_and_wait(&store, &scope, 20);
    guard.stop();
    drop(guard);
    let (entries, objects) = snapshot(&store, &journal);
    drop(store);

    // The start after: all of them, still the one line.
    let (store, problems) = Store::open(cfg, None);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert_eq!(
        snapshot(&store, &journal),
        (entries, objects),
        "the copies taken after the restart are there at the start after"
    );
}

/// Lot 315 (external bug hunt 1.4, BUG-93, through the real guard): two
/// processes of one tree (two `sh` children of this test) write-open the
/// same file one after the other. The second one's write-open is recorded
/// with its lineage (this process in it) and with the file's identity, and
/// a restore of the tree (`--pid` this process) puts the original back in
/// place — on `main` the second writer was "another writer": kept both.
#[test]
#[ignore = "requires root (fanotify, a tmpfs mount); lab: nn-lab.sh test-one cow_privileged_e2e"]
fn two_writers_of_one_tree_are_its_attack() {
    use northnarrow_agent::cow::restore::Selector;
    use northnarrow_agent::cow::store::RestoreBy;
    use northnarrow_agent::cow::trust::ProcId;
    let dir = tempfile::Builder::new()
        .prefix("nn-cow-tree")
        .tempdir()
        .unwrap();
    let scope = dir.path().join("scope");
    std::fs::create_dir(&scope).unwrap();
    let mounted = Command::new("mount")
        .args(["-t", "tmpfs", "-o", "size=64m", "nn-cow-test"])
        .arg(&scope)
        .status()
        .unwrap();
    assert!(mounted.success(), "mount a tmpfs at the scope (root?)");
    let _mount = Mount(scope.clone());
    let file = scope.join("report.odt");
    std::fs::write(&file, b"original").unwrap();
    let cfg = CowConfig::parse(&format!(
        "enabled = true\nscope = {} mark=mount\n",
        scope.display()
    ))
    .unwrap();
    let (store, problems) = Store::open(cfg, None);
    assert!(problems.is_empty(), "{problems:?}");
    let guard = Runtime::start(Arc::clone(&store), AuthSessionTracker::new(dir.path()))
        .expect("the guard starts");
    // each writer's copy committed before the next one opens the file (a
    // write-open is recorded for a file the index holds)
    let scripts = ["printf 'half encrypted' > \"$0\"", "printf ' and the rest' >> \"$0\""];
    for (i, script) in scripts.iter().enumerate() {
        let ok = Command::new("sh")
            .arg("-c")
            .arg(script)
            .arg(&file)
            .status()
            .unwrap();
        assert!(ok.success());
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while store.index.lock().entry_count(0) < i + 1 {
            assert!(
                std::time::Instant::now() < deadline,
                "copy {} not committed within 20 s",
                i + 1
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    guard.stop();
    drop(guard);
    let me = ProcId {
        pid: std::process::id(),
        start: 0,
    };
    let first = store
        .index
        .lock()
        .entries()
        .min_by_key(|e| e.id)
        .unwrap()
        .clone();
    let post = store.index.lock().post_writes(&first.file.id(), 0);
    assert!(
        post.iter().any(|p| p.in_tree_of(me) && p.file.may_be(&first.file.id())),
        "the second writer's write-open, with its lineage: {post:?}"
    );
    let rep = store.restore(
        &Selector {
            roots: vec![me],
            since_ms: None,
        },
        false,
        &RestoreBy::Admin {
            key_fp: "lot315".into(),
        },
    );
    assert_eq!(rep.restored, 1, "{:?}", rep.rows);
    assert_eq!(std::fs::read(&file).unwrap(), b"original");
}
