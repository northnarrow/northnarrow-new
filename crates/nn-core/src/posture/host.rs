//! What the posture needs from the host it runs on (Wave 4 restructure,
//! R08a, lab PR 250).
//!
//! The posture judges a process by what the kernel says about it. Its
//! lineage reads the process table for the hops the spawn cache does not
//! hold (`exe`, `status`, `cmdline`), places a process by its login uid,
//! terminal and cgroup (`loginuid`, `stat`, `cgroup`), checks a cached
//! exec against the process its pid names now (the start `stat` shows, in
//! clock ticks of the boot clock, against the monotonic clock of the
//! events, less the time the host spent suspended), finds a container's
//! mount namespace and root overlay (`ns/mnt`, `mountinfo`), and reads the
//! host's subordinate-id ranges, its accounts and the owners of container
//! storage; the stack exemption reads the watchdog's pidfile, its `exe`
//! and its start. Those reads and the clocks are here, as a trait the host
//! implements (the agent: `LinuxHost`, in its `posture_host_linux` module,
//! where `/proc`, `st_uid`, `clock_gettime` and `sysconf` are). Each is
//! the call the posture code made itself before R08a — lab PR 250 moved
//! the calls, not their arguments: the posture builds the paths (under the
//! process table's root and the host's, a fixture directory in tests and
//! replays) and the host reads them.
//!
//! The host is a type parameter of the posture's types (as
//! `nn_evidence::chain_host::ChainHost` is of the chains' and
//! [`crate::content_host::ContentHost`] of the content's): static
//! functions, no state, no global, nothing to register. The file reads
//! take their path as `std::fs` does (`impl AsRef<Path>`), so each call
//! passes what it passed before.

use std::fmt::Debug;
use std::io;
use std::path::{Path, PathBuf};

/// The host's reads and clocks the posture uses. A unit type: the posture's
/// types hold it as a parameter only (hence `Copy`, `Default`, `Debug`).
pub trait PostureHost: Copy + Default + Debug + Send + Sync + 'static {
    /// The process table's root: `/proc`.
    const PROC_ROOT: &'static str;

    /// The root of the host's files (its accounts, its container storage):
    /// `/`.
    const HOST_ROOT: &'static str;

    /// `path` read as text: an entry of the process table, an account
    /// file, the watchdog's pidfile.
    fn read_to_string<P: AsRef<Path>>(path: P) -> io::Result<String>;

    /// `path` read as bytes (a process's `cmdline`).
    fn read<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>>;

    /// The target of the link at `path`, as the host resolves it (a
    /// process's `exe`, its `ns/mnt`).
    fn read_link<P: AsRef<Path>>(path: P) -> io::Result<PathBuf>;

    /// The entries of the directory at `path` (the process table, R08b: the
    /// security-tool detector's scan of it).
    fn read_dir<P: AsRef<Path>>(path: P) -> io::Result<std::fs::ReadDir>;

    /// `path` is a directory (a process's entry in the process table).
    fn is_dir(path: &Path) -> bool;

    /// `path` exists.
    fn exists(path: &Path) -> bool;

    /// The owner (uid) of the directory at `path`, its final symlink not
    /// followed; `None` when it is not a directory or cannot be read.
    fn dir_owner<P: AsRef<Path>>(path: P) -> Option<u32>;

    /// The time the host has spent suspended so far, ns: the boot clock
    /// less the monotonic clock (`CLOCK_BOOTTIME` − `CLOCK_MONOTONIC`).
    fn suspended_ns() -> u64;

    /// Nanoseconds per clock tick of the process table's start times.
    fn clock_tick_ns() -> u64;

    /// The monotonic clock now, ns (`CLOCK_MONOTONIC`): the clock of the
    /// kernel's event timestamps.
    fn monotonic_ns() -> u64;
}

/// What the posture's triggers and machine consult in the agent's other
/// modules (R08a, lab PR 250), each until the lot that moves it below the
/// posture: the trusted-installer window (`anti_tamper`; R04b splits it)
/// and the capability a verified signed unlock mints (`anti_tamper`; R04b).
/// The agent's `LinuxHost` implements it with the calls the posture made.
///
/// R08b (lab PR 251): the rule engine is nn-core's, so the triggers call
/// the shapes they share with its rules (NN-L-FIM-024's bait tamper,
/// NN-L-EPG-001/002's event, R020's reverse shell, the staging directories)
/// and the machine reads the engine's per-rule policy themselves; the trait
/// lost that half. R08c (lab PR 252): the ransomware tracker and the
/// security-tool detector, nn-core's since R08b and generic over the
/// decision host, are named by the machine and the triggers themselves,
/// which take that host ([`crate::decision::host::DecisionHost`], on top of
/// this trait); the trait lost the two judges.
pub trait PostureAgent: PostureHost {
    /// The trusted-installer window (lab PR 162).
    type InstallerWindow: Send + Sync + 'static;

    /// The window is open now.
    fn installer_window_open(window: &Self::InstallerWindow) -> bool;

    /// The capability a verified signed unlock mints: the machine hands it
    /// to its release hook (lab PR 217), it never makes one.
    type UnlockToken: Send + 'static;
}

/// The posture's own tests: a portable host. Its files are the machine's
/// (`std::fs`: a fixture directory stands for the process table, or the
/// test's own `/proc`); a directory is owned by [`testing::TEST_OWNER`];
/// it is never suspended, its clock ticks 100 times a second, and its
/// monotonic clock reads an hour of uptime when the tests begin. What is
/// Linux about the agent's host (`lstat`'s owner, the kernel's clocks) is
/// tested with that host, in the agent (`posture_host_linux`).
#[cfg(test)]
pub(crate) mod testing {
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::LazyLock;
    use std::time::Instant;

    use super::{PostureAgent, PostureHost};

    /// The owner of every directory on the test host: the fixtures' user,
    /// not root (a package manager a user runs is not root's transaction).
    pub(crate) const TEST_OWNER: u32 = 1000;

    /// The host's uptime when the tests begin: an hour.
    const UPTIME_AT_START_NS: u64 = 3_600 * 1_000_000_000;

    /// When the tests began.
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);

    /// Plain `std`, every directory [`TEST_OWNER`]'s, the clocks above.
    #[derive(Debug, Clone, Copy, Default)]
    pub(crate) struct TestHost;

    impl PostureHost for TestHost {
        const PROC_ROOT: &'static str = "/proc";

        const HOST_ROOT: &'static str = "/";

        fn read_to_string<P: AsRef<Path>>(path: P) -> io::Result<String> {
            std::fs::read_to_string(path)
        }

        fn read<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
            std::fs::read(path)
        }

        fn read_link<P: AsRef<Path>>(path: P) -> io::Result<PathBuf> {
            std::fs::read_link(path)
        }

        fn read_dir<P: AsRef<Path>>(path: P) -> io::Result<std::fs::ReadDir> {
            std::fs::read_dir(path)
        }

        fn is_dir(path: &Path) -> bool {
            path.is_dir()
        }

        fn exists(path: &Path) -> bool {
            path.exists()
        }

        fn dir_owner<P: AsRef<Path>>(path: P) -> Option<u32> {
            std::fs::symlink_metadata(path)
                .ok()
                .filter(|m| m.is_dir())
                .map(|_| TEST_OWNER)
        }

        fn suspended_ns() -> u64 {
            0
        }

        fn clock_tick_ns() -> u64 {
            10_000_000
        }

        fn monotonic_ns() -> u64 {
            UPTIME_AT_START_NS + START.elapsed().as_nanos() as u64
        }
    }

    /// What the posture consults in the agent, as its tests need it: the
    /// window whether it is open; the unlock capability is `()`. (R08b, lab
    /// PR 251: the engine's shapes and policy are read from the engine
    /// itself, nn-core's; R08c, lab PR 252: so are its judges, which no
    /// test of the posture wires — none fires.)
    impl PostureAgent for TestHost {
        type InstallerWindow = bool;

        fn installer_window_open(window: &bool) -> bool {
            *window
        }

        type UnlockToken = ();
    }

    /// R08b (lab PR 251): the engine's tests read shipped lists through the
    /// same host: plain `std` (a final symlink followed, no refusal of its
    /// own), as the content code's portable test host.
    impl crate::content_host::ContentHost for TestHost {
        fn open_read_nofollow(path: &Path) -> io::Result<std::fs::File> {
            std::fs::OpenOptions::new().read(true).open(path)
        }
        fn is_symlink_refusal(_err: &io::Error) -> bool {
            false
        }
    }

    /// A symbolic link at `link` to `target`, as the fixtures of the process
    /// table need one (`exe`, `ns/mnt`): `std::fs::soft_link`, the spelling
    /// of `symlink(2)` that builds on every target — deprecated because
    /// Windows has two kinds of link; these fixtures are a Linux process
    /// table, read back with `std::fs::read_link`.
    #[allow(deprecated)]
    pub(crate) fn symlink<P: AsRef<Path>, Q: AsRef<Path>>(target: P, link: Q) -> io::Result<()> {
        std::fs::soft_link(target, link)
    }
}
