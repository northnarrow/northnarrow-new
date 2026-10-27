//! The Linux host of the posture: the reads and clocks of nn-core's
//! [`PostureHost`] (Wave 4 restructure, R08a, lab PR 250), as the posture
//! code made them itself before — `std::fs` on the paths it builds (under
//! `/proc` and `/`, a fixture directory in tests and replays), the owner of
//! a container-storage directory (`st_uid`), and the clocks
//! (`clock_gettime(CLOCK_BOOTTIME)`, `clock_gettime(CLOCK_MONOTONIC)`,
//! `sysconf(_SC_CLK_TCK)`), with the same arguments. The host is the
//! chains' one ([`LinuxHost`], `chain_host_linux`): one type, the agent's.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use nn_core::posture::host::PostureHost;

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
