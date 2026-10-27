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
