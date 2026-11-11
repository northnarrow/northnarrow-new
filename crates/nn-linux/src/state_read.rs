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

/// Lot 311 (the review of #538, F9): a configuration file a judge reads (a
/// drop-in, an `EnvironmentFile=`) — a regular file only, opened without
/// blocking, at most `antitamper_bpf`'s 1 MiB, its bytes made text
/// ([`antitamper_bpf::host_dropins::read_lossy`]): a FIFO no longer stalls
/// the judge, nor `/dev/zero` exhausts it.
pub fn read_config(path: &Path) -> io::Result<String> {
    antitamper_bpf::host_dropins::read_lossy(path)
}

/// Lot 311 (the review of #538): a condition a part of the agent finds and
/// sees end — a table it cannot read, lines of it it cannot parse, roots the
/// kernel's map refuses. While it holds it is a degradation of `source`
/// (listed by `nn-admin status`, counted against the trust level, signed in
/// the audit chain): reported once, again only when what it says changes;
/// withdrawn when it ends — and signed before that (`degradation::withdraw`
/// signs what the flush has not yet), so a condition shorter than the
/// flush period still leaves its record in the chain.
#[derive(Debug)]
pub struct Condition {
    source: &'static str,
    holding: Option<String>,
}

impl Condition {
    pub const fn new(source: &'static str) -> Self {
        Condition {
            source,
            holding: None,
        }
    }

    /// It holds, as `detail` says.
    pub fn holds(&mut self, detail: String) {
        if self.holding.as_deref() == Some(detail.as_str()) {
            return;
        }
        if self.holding.is_some() {
            crate::boot::degradation::withdraw(self.source, &[]);
        }
        tracing::warn!(source = self.source, detail = %detail, "degraded");
        crate::boot::degradation::report(self.source, &detail);
        self.holding = Some(detail);
    }

    /// It ended: withdrawn (its signed record stays in the chain).
    pub fn ended(&mut self) {
        if self.holding.take().is_some() {
            tracing::info!(source = self.source, "no longer degraded");
            crate::boot::degradation::withdraw(self.source, &[]);
        }
    }

    /// It holds now.
    pub fn holding(&self) -> bool {
        self.holding.is_some()
    }
}

/// Lot 311 (F4): the rule of a reader that publishes what it read of the
/// kernel's state (the guarded roots, the slices): when a read fails, what
/// it last published stays in force — never an empty set in its place —
/// and the failure is a [`Condition`] of `source` while the reads fail.
/// The caller publishes on a good read only; this keeps the account.
#[derive(Debug)]
pub struct LastGood {
    what: &'static str,
    unread: Condition,
}

impl LastGood {
    /// A reader of `what` (the file, in words) for the part `source`.
    pub const fn new(source: &'static str, what: &'static str) -> Self {
        LastGood {
            what,
            unread: Condition::new(source),
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
        if !self.unread.holding() {
            tracing::warn!(
                what = self.what,
                error = %e,
                "kernel state unreadable — the last good reading stays in force"
            );
        }
        let detail = self.detail();
        self.unread.holds(detail);
    }

    /// A read succeeded: the degradation is withdrawn.
    pub fn ok(&mut self) {
        self.unread.ended();
    }

    /// The reads fail now.
    pub fn failing(&self) -> bool {
        self.unread.holding()
    }
}

/// Lot 311 (the review of #538, F2): the lines of a mount table that are
/// not in the kernel's shape are a [`Condition`] (`rows`) while there are
/// any — never dropped in silence: their mounts are not judged by the
/// caller (`what`, in words).
pub fn mount_rows(rows: &mut Condition, table: &crate::mountinfo::MountTable, what: &str) {
    match table.malformed.first() {
        None => rows.ended(),
        Some(first) => rows.holds(format!(
            "{} line(s) of the mount table are not in the kernel's shape ({}, line {}{}): \
             {what} does not judge their mounts",
            table.malformed.len(),
            first.why,
            first.line,
            first
                .mount_point
                .as_ref()
                .map(|p| format!(", mount point {}", p.to_string_lossy()))
                .unwrap_or_default()
        )),
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
        let _g = crate::boot::degradation::TEST_LOCK.lock();
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

    /// Lot 311 (the review of #538, F2): lines of a mount table that are
    /// not in the kernel's shape are a degradation while there are any —
    /// never dropped in silence — and it ends with them.
    #[test]
    fn unparsed_mount_lines_are_a_degradation_while_they_last() {
        let _g = crate::boot::degradation::TEST_LOCK.lock();
        let mut rows = Condition::new("lot311_test_rows");
        let mine = || {
            crate::boot::degradation::entries()
                .into_iter()
                .filter(|d| d.source == "lot311_test_rows")
                .map(|d| d.detail)
                .collect::<Vec<_>>()
        };
        let good = crate::mountinfo::parse(b"30 1 0:5 / /tmp rw - tmpfs tmpfs rw\n");
        mount_rows(&mut rows, &good, "the test");
        assert!(mine().is_empty());
        let odd = crate::mountinfo::parse(
            b"30 1 0:5 / /tmp rw - tmpfs tmpfs rw\n57 1 0:44 / /home/u/mnt rw fuse.x x rw\n",
        );
        mount_rows(&mut rows, &odd, "the test");
        let d = mine();
        assert_eq!(d.len(), 1, "{d:?}");
        assert!(
            d[0].contains("1 line(s)") && d[0].contains("/home/u/mnt"),
            "{d:?}"
        );
        mount_rows(&mut rows, &odd, "the test");
        assert_eq!(mine().len(), 1, "reported once");
        mount_rows(&mut rows, &good, "the test");
        assert!(mine().is_empty(), "withdrawn");
        assert!(!rows.holding());
    }
}
