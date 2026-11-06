//! The Linux host of the posture: the reads and clocks of nn-core's
//! [`PostureHost`] (Wave 4 restructure, R08a, lab PR 250), as the posture
//! code made them itself before — `std::fs` on the paths it builds (under
//! `/proc` and `/`, a fixture directory in tests and replays), the owner of
//! a container-storage directory (`st_uid`), and the clocks
//! (`clock_gettime(CLOCK_BOOTTIME)`, `clock_gettime(CLOCK_MONOTONIC)`,
//! `sysconf(_SC_CLK_TCK)`), with the same arguments. The host is the
//! chains' one ([`LinuxHost`], `chain_host_linux`): one type, the agent's.
//!
//! And what the posture consults in the agent's other modules
//! ([`PostureAgent`]): the trusted-installer window, the unlock capability
//! — the calls the triggers and the machine made, each until its lot moves
//! it below the posture (R04b). R08b (lab PR 251): the rule engine's shapes
//! and its per-rule policy left the trait, the engine being nn-core's with
//! the posture; R08c (lab PR 252): so did the ransomware and security-tool
//! judges, which the posture names itself.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use nn_core::posture::host::{PostureAgent, PostureHost};

use crate::anti_tamper::network_isolate::UnlockToken;
use crate::anti_tamper::trusted_installer::TrustedInstallerOverride;
use crate::chain_host_linux::LinuxHost;

impl PostureHost for LinuxHost {
    const PROC_ROOT: &'static str = "/proc";

    const HOST_ROOT: &'static str = "/";

    fn read_to_string<P: AsRef<Path>>(path: P) -> io::Result<String> {
        fs::read_to_string(path)
    }

    fn read<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
        fs::read(path)
    }

    fn read_link<P: AsRef<Path>>(path: P) -> io::Result<PathBuf> {
        fs::read_link(path)
    }

    fn read_dir<P: AsRef<Path>>(path: P) -> io::Result<fs::ReadDir> {
        fs::read_dir(path)
    }

    fn is_dir(path: &Path) -> bool {
        path.is_dir()
    }

    fn exists(path: &Path) -> bool {
        path.exists()
    }

    /// `lstat(2)`'s `st_uid`, for a directory only.
    fn dir_owner<P: AsRef<Path>>(path: P) -> Option<u32> {
        fs::symlink_metadata(path)
            .ok()
            .filter(|m| m.is_dir())
            .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
    }

    /// `open(2)` with `O_PATH | O_CLOEXEC` and `fstat(2)` of that file:
    /// `/proc/<pid>/exe` opens the image the kernel executed (its magic
    /// link, no path walked in the process's mount namespace), a host path
    /// the file the agent sees there.
    fn file_id<P: AsRef<Path>>(path: P) -> Option<(u64, u64)> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(path)
            .ok()?;
        let meta = file.metadata().ok()?;
        Some((meta.dev(), meta.ino()))
    }

    fn suspended_ns() -> u64 {
        let now = |clock| {
            let mut ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: a valid clock id and a timespec to fill.
            unsafe { libc::clock_gettime(clock, &mut ts) };
            ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
        };
        now(libc::CLOCK_BOOTTIME).saturating_sub(now(libc::CLOCK_MONOTONIC))
    }

    /// `sysconf(_SC_CLK_TCK)`, read once (10 ms when it answers nothing).
    fn clock_tick_ns() -> u64 {
        static TICK: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        *TICK.get_or_init(|| {
            // SAFETY: sysconf has no preconditions.
            let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
            if hz > 0 {
                1_000_000_000 / hz as u64
            } else {
                10_000_000
            }
        })
    }

    fn monotonic_ns() -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: a valid clock id and a timespec to fill.
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }
}

impl PostureAgent for LinuxHost {
    type InstallerWindow = TrustedInstallerOverride;

    fn installer_window_open(window: &TrustedInstallerOverride) -> bool {
        window.is_window_open()
    }

    /// Minted only by `anti_tamper` (`AdminAuth`, once a signed unlock
    /// verified).
    type UnlockToken = UnlockToken;
}

/// What is Linux about the posture's host: a directory's owner from
/// `lstat`, the kernel's links, the three clocks. The posture's own tests
/// (nn-core's) run on a portable test host.
#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn clock(id: libc::clockid_t) -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: a valid clock id and a timespec to fill.
        unsafe { libc::clock_gettime(id, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }

    /// A directory's owner is `lstat`'s: the test's uid for a directory it
    /// made; nothing for a file, a missing path, or a symlink to a
    /// directory (the final link is not followed).
    #[test]
    fn a_directory_is_owned_by_its_st_uid_and_a_link_to_one_by_nobody() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("storage");
        fs::create_dir(&dir).unwrap();
        fs::write(tmp.path().join("file"), b"x").unwrap();
        symlink(&dir, tmp.path().join("link")).unwrap();
        // SAFETY: getuid has no preconditions.
        let me = unsafe { libc::getuid() };
        assert_eq!(LinuxHost::dir_owner(&dir), Some(me));
        assert_eq!(LinuxHost::dir_owner(tmp.path().join("file")), None);
        assert_eq!(LinuxHost::dir_owner(tmp.path().join("absent")), None);
        assert_eq!(LinuxHost::dir_owner(tmp.path().join("link")), None);
        assert!(LinuxHost::is_dir(&dir) && LinuxHost::exists(&dir));
        assert!(!LinuxHost::is_dir(&tmp.path().join("file")));
    }

    /// The process table is `/proc`: this process's entry is there, and its
    /// `exe` link is what the kernel executed.
    #[test]
    fn the_process_table_is_proc() {
        assert_eq!(LinuxHost::PROC_ROOT, "/proc");
        assert_eq!(LinuxHost::HOST_ROOT, "/");
        let me = Path::new(LinuxHost::PROC_ROOT).join(std::process::id().to_string());
        assert!(LinuxHost::is_dir(&me));
        assert_eq!(
            LinuxHost::read_link(me.join("exe")).unwrap(),
            std::env::current_exe().unwrap()
        );
        let stat = LinuxHost::read_to_string(me.join("stat")).unwrap();
        assert!(
            stat.starts_with(&format!("{} (", std::process::id())),
            "{stat}"
        );
        assert!(LinuxHost::read(me.join("cmdline")).is_ok_and(|b| !b.is_empty()));
    }

    /// The final check of #495 (C1): a process's image is the file its
    /// `exe` opens — the kernel's link, not a path: this test's own binary
    /// is `current_exe`'s file, a copy of it another; a child running a
    /// copied `sleep` keeps that file's identity after another file is
    /// renamed over its path (an upgrade), which the path then no longer
    /// names; a missing path has none. Lot 288: the child's link is read
    /// once its exec has replaced its image ([`exec_done`]).
    #[test]
    fn a_process_s_image_is_the_file_its_exe_opens() {
        let me = Path::new(LinuxHost::PROC_ROOT).join(std::process::id().to_string());
        let own = LinuxHost::file_id(me.join("exe"));
        assert!(own.is_some());
        assert_eq!(own, LinuxHost::file_id(std::env::current_exe().unwrap()));
        let tmp = tempfile::TempDir::new().unwrap();
        let sleep = tmp.path().join("sleep");
        fs::copy("/bin/sleep", &sleep).unwrap();
        assert_ne!(LinuxHost::file_id(&sleep), own);
        assert_eq!(LinuxHost::file_id(tmp.path().join("absent")), None);
        // the device counts: `/proc`'s and `/sys`'s roots are each inode 1
        // of their own file system
        let (proc_root, sys_root) = (LinuxHost::file_id("/proc"), LinuxHost::file_id("/sys"));
        assert!(proc_root.is_some() && sys_root.is_some());
        assert_ne!(proc_root, sys_root);
        // another test's fork may hold the copy's write descriptor until
        // its exec (the parallel harness): `ETXTBSY` for a moment
        let mut child = (0..200)
            .find_map(
                |_| match std::process::Command::new(&sleep).arg("30").spawn() {
                    Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        None
                    }
                    other => Some(other.unwrap()),
                },
            )
            .expect("the copy of sleep runs");
        let exe = Path::new(LinuxHost::PROC_ROOT)
            .join(child.id().to_string())
            .join("exe");
        let started = LinuxHost::file_id(&sleep);
        let running = exec_done(&exe, started, EXEC_DONE_WITHIN);
        let upgrade = tmp.path().join("sleep.new");
        fs::copy("/bin/sleep", &upgrade).unwrap();
        fs::rename(&upgrade, &sleep).unwrap();
        let after = LinuxHost::file_id(&exe);
        let path_now = LinuxHost::file_id(&sleep);
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(started.is_some());
        assert_eq!(running, started);
        assert_eq!(after, started);
        assert_ne!(path_now, started);
    }

    /// Lot 288: what `exe` (a child's `/proc/<pid>/exe`) opens once the
    /// child's exec has replaced its image — `want` as soon as it does, the
    /// last reading after `within` otherwise (and the caller's
    /// assertion fails on it). `spawn` returns when the kernel wakes the
    /// parent of a `vfork` child (glibc's `posix_spawn`, `CLONE_VFORK`): in
    /// `exec_mmap`, before the child's `mm` is the new image's. Until then
    /// the link names the parent's image (the shared `mm`: this test
    /// binary), or no file: what the test read under the parallel harness
    /// (lot 275's test failed in CI and in lot 283c's gates, and passed
    /// when re-run).
    fn exec_done(
        exe: &Path,
        want: Option<(u64, u64)>,
        within: std::time::Duration,
    ) -> Option<(u64, u64)> {
        let until = std::time::Instant::now() + within;
        loop {
            let now = LinuxHost::file_id(exe);
            if now == want || std::time::Instant::now() >= until {
                return now;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    /// Lot 288: how long a spawned child's exec may take to replace its
    /// image (a loaded host, the parallel harness): far longer than it ever
    /// does, bounded so a wrong `exe` still fails the test.
    const EXEC_DONE_WITHIN: std::time::Duration = std::time::Duration::from_secs(10);

    /// Lot 288: [`exec_done`] waits for the exec only — a link that never
    /// opens the file wanted is returned as it is, after the bound.
    #[test]
    fn exec_done_returns_what_the_link_opens_and_never_another_file() {
        let me = Path::new(LinuxHost::PROC_ROOT)
            .join(std::process::id().to_string())
            .join("exe");
        let own = LinuxHost::file_id(&me);
        assert!(own.is_some());
        let within = std::time::Duration::from_millis(300);
        let at = std::time::Instant::now();
        assert_eq!(exec_done(&me, own, within), own);
        assert!(at.elapsed() < within);
        let tmp = tempfile::TempDir::new().unwrap();
        fs::write(tmp.path().join("other"), b"x").unwrap();
        let other = LinuxHost::file_id(tmp.path().join("other"));
        assert!(other.is_some() && other != own);
        let at = std::time::Instant::now();
        assert_eq!(exec_done(&me, other, within), own);
        assert!(at.elapsed() >= within);
    }

    /// The clocks are the kernel's: the monotonic one between two readings
    /// of `CLOCK_MONOTONIC`, the suspended time the boot clock's lead over
    /// it (within a millisecond: two readings apart), the tick
    /// `sysconf(_SC_CLK_TCK)`'s.
    #[test]
    fn the_clocks_are_the_kernels() {
        let before = clock(libc::CLOCK_MONOTONIC);
        let now = LinuxHost::monotonic_ns();
        let after = clock(libc::CLOCK_MONOTONIC);
        assert!(
            before <= now && now <= after,
            "{before} <= {now} <= {after}"
        );
        let lead = clock(libc::CLOCK_BOOTTIME).saturating_sub(clock(libc::CLOCK_MONOTONIC));
        let suspended = LinuxHost::suspended_ns();
        assert!(suspended.abs_diff(lead) < 1_000_000, "{suspended} ~ {lead}");
        // SAFETY: sysconf has no preconditions.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
        assert_eq!(LinuxHost::clock_tick_ns(), 1_000_000_000 / hz);
    }
}
