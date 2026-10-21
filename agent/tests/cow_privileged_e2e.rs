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
    let (store, problems) = Store::open(cfg);
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
