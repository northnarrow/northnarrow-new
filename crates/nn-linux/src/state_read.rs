//! Lot 311 (third bug hunt, family F4, and the triage's N6): the kernel's
//! state files read as text that never fails on its encoding.
//!
//! `/proc/<pid>/stat` and `/proc/<pid>/status` carry the process's `comm`
//! byte for byte, and any process sets its own: `prctl(PR_SET_NAME)`, a
//! write to `/proc/self/comm`, or simply the name of the file it executed
//! (`/tmp/$'\xff\xfe'`). `std::fs::read_to_string` refuses such a file
//! (`InvalidData`), and a reader that took the refusal for "no such
//! process" went blind on a process that chose its name: the response's
//! capture reported every kill of it failed (`EIO`) and left it running
//! (lab, ubuntu2404: R001's kill of a system account's exec from `/tmp`).
//! The same holds for a cgroup's name, which a user names in the subtree
//! systemd delegates to it.
//!
//! [`read_state`] reads the bytes and replaces what is not UTF-8 with
//! U+FFFD ([`nn_core::posture::host::state_text`]): the fields the readers
//! parse (the numbers after the `(comm)` field, `Uid:`, a cgroup path of
//! ours) are ASCII and read as before, and a replaced byte never turns a
//! name into an ASCII one another process could hold. Lot 311 moves the
//! response's and the COMBAT ladder's reads onto it.

use std::io;
use std::path::Path;

/// The file at `path` as text, bytes that are not UTF-8 replaced by U+FFFD.
/// Fails only when the file cannot be read.
pub fn read_state<P: AsRef<Path>>(path: P) -> io::Result<String> {
    std::fs::read(path).map(nn_core::posture::host::state_text)
}

/// Lot 311 (F4): the rule of a reader that publishes what it read of the
/// kernel's state (the guarded roots, the slices): when a read fails, what
/// it last published stays in force — never an empty set in its place —
/// and the failure is a degradation of `source` (the registry: listed by
/// `nn-admin status`, signed in the audit chain), reported once while the
/// reads fail and withdrawn at the next good one. The caller publishes on
/// a good read only; this keeps the account.
#[derive(Debug)]
pub struct LastGood {
    source: &'static str,
    what: &'static str,
    failing: bool,
}

impl LastGood {
    /// A reader of `what` (the file, in words) for the part `source`.
    pub const fn new(source: &'static str, what: &'static str) -> Self {
        LastGood {
            source,
            what,
            failing: false,
        }
    }

    /// The degradation's text.
    pub fn detail(&self) -> String {
        format!(
            "{} could not be read: what was last read of it stays in force",
            self.what
        )
    }

    /// A read failed: logged and reported (once while the reads fail).
    pub fn failed(&mut self, e: &io::Error) {
        if self.failing {
            return;
        }
        self.failing = true;
        tracing::warn!(
            source = self.source,
            what = self.what,
            error = %e,
            "kernel state unreadable — the last good reading stays in force"
        );
        crate::boot::degradation::report(self.source, &self.detail());
    }

    /// A read succeeded: a degradation reported for the failures is
    /// withdrawn (its signed record stays in the chain).
    pub fn ok(&mut self) {
        if std::mem::take(&mut self.failing) {
            tracing::info!(
                source = self.source,
                what = self.what,
                "kernel state readable again"
            );
            crate::boot::degradation::withdraw(self.source, &[]);
        }
    }

    /// The reads fail now.
    pub fn failing(&self) -> bool {
        self.failing
    }
}

/// Test doors: a process whose `comm` is not UTF-8.
#[cfg(any(test, feature = "test-util"))]
pub mod testing {
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};

    /// The `comm` the kernel gives a process that executes a file named so.
    pub const NON_UTF8_COMM: &[u8] = b"\xff\xfe";

    /// A shell (`/bin/sh`) run through a symlink named [`NON_UTF8_COMM`]:
    /// the kernel sets its `comm` to the name of the file it executed, so
    /// its `/proc/<pid>/stat` and `status` are not UTF-8 from its first
    /// instruction — what an unprivileged process gets for itself. It loops
    /// on `sleep 1` (one process of that name, alive throughout: a shell
    /// does not dispatch on `argv[0]`, as a multicall coreutils — uutils on
    /// Ubuntu 26.04, the CI's image — does). Killed and reaped on drop; the
    /// symlink's directory removed.
    pub struct NonUtf8Comm {
        pub child: Child,
        dir: PathBuf,
    }

    impl NonUtf8Comm {
        pub fn pid(&self) -> u32 {
            self.child.id()
        }
    }

    impl Drop for NonUtf8Comm {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A fixture process table's `<root>/<pid>/stat`, `status` and `comm`
    /// for a process whose `comm` is [`NON_UTF8_COMM`], as the kernel writes
    /// them: parent `ppid`, real uid `uid`, start `ticks` (field 22).
    pub fn write_non_utf8_proc(root: &std::path::Path, pid: u32, ppid: u32, uid: u32, ticks: u64) {
        let dir = root.join(pid.to_string());
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let mut stat = format!("{pid} (").into_bytes();
        stat.extend_from_slice(NON_UTF8_COMM);
        stat.extend_from_slice(
            format!(") S {ppid} {pid} {pid} 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {ticks} 0 0\n")
                .as_bytes(),
        );
        std::fs::write(dir.join("stat"), stat).expect("fixture stat");
        let mut status = b"Name:\t".to_vec();
        status.extend_from_slice(NON_UTF8_COMM);
        status.extend_from_slice(
            format!(
                "\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t{ppid}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nThreads:\t1\n"
            )
            .as_bytes(),
        );
        std::fs::write(dir.join("status"), status).expect("fixture status");
        let mut comm = NON_UTF8_COMM.to_vec();
        comm.push(b'\n');
        std::fs::write(dir.join("comm"), comm).expect("fixture comm");
    }

    /// Start one, sleeping `secs`, and wait until the kernel shows its
    /// `comm` (the exec done).
    pub fn sleeper_with_non_utf8_comm(secs: u32) -> NonUtf8Comm {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "nn-n6-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("n6 dir");
        let link = dir.join(std::ffi::OsStr::from_bytes(NON_UTF8_COMM));
        std::os::unix::fs::symlink("/bin/sh", &link).expect("n6 symlink");
        let child = Command::new(&link)
            .arg("-c")
            .arg(format!(
                "i=0; while [ $i -lt {secs} ]; do sleep 1; i=$((i + 1)); done"
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the n6 sleeper");
        let comm = PathBuf::from(format!("/proc/{}/comm", child.id()));
        for _ in 0..500 {
            if std::fs::read(&comm).is_ok_and(|c| c.starts_with(NON_UTF8_COMM)) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        NonUtf8Comm { child, dir }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    /// N6: the kernel shows such a process's `stat` and `status` with its
    /// `comm` as it is — not UTF-8 — and the reader still reads them.
    #[test]
    fn a_comm_that_is_not_utf8_does_not_blind_the_state_reader() {
        let p = sleeper_with_non_utf8_comm(30);
        let stat = format!("/proc/{}/stat", p.pid());
        let status = format!("/proc/{}/status", p.pid());
        assert!(
            std::fs::read_to_string(&stat).is_err(),
            "the premise: the strict reader refuses the file"
        );
        let text = read_state(&stat).unwrap();
        assert!(
            text.starts_with(&format!("{} (\u{fffd}\u{fffd}) ", p.pid())),
            "{text}"
        );
        let text = read_state(&status).unwrap();
        assert!(text.lines().any(|l| l.starts_with("PPid:")), "{text}");
        assert!(read_state("/proc/nonexistent-n6").is_err());
    }

    /// Lot 311 (F4): a failed read is one degradation of its source while
    /// the reads fail, withdrawn by the next good one.
    #[test]
    fn a_failed_read_is_one_degradation_until_a_good_one() {
        let mut r = LastGood::new("lot311_test_reader", "the test table");
        let has = || {
            crate::boot::degradation::entries()
                .iter()
                .filter(|d| d.source == "lot311_test_reader")
                .count()
        };
        r.ok();
        assert_eq!(has(), 0);
        let e = io::Error::from_raw_os_error(libc::EMFILE);
        r.failed(&e);
        r.failed(&e);
        assert!(r.failing());
        assert_eq!(has(), 1);
        assert!(crate::boot::degradation::entries()
            .iter()
            .any(|d| d.source == "lot311_test_reader" && d.detail == r.detail()));
        r.ok();
        assert!(!r.failing());
        assert_eq!(has(), 0);
    }
}
