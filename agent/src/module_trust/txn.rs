//! Lot 370 (F10-2): the package transactions alive — a package manager
//! holding its lock, not stopped — that the module judge's write history may
//! name.
//!
//! The kernel's write history (`common::module_judge::ModuleWrite`) names,
//! for a module file a package manager's lineage wrote, that package manager
//! (its thread group and start), read at the write: not stopped, traced or
//! frozen, the writer's marks free of injected code. That is not yet a
//! transaction: any root process descending from a package manager — a
//! pager `apt changelog` started, `dpkg -l`'s — wrote "in" one. The
//! controller samples the package managers' lock files' holders here
//! (`/proc/locks`, each holder's `/proc/<pid>/stat`: not stopped), every
//! poll, and vouches for a file changed since boot only when the
//! transaction its history names was seen holding the lock.
//!
//! The holder is matched by its lock file's inode number (a btrfs
//! subvolume's `stat` device is not the one `/proc/locks` prints), and by
//! the thread group and start the kernel recorded. Residual, said: a
//! package manager the agent never saw holding its lock (a transaction
//! shorter than a poll, about a quarter of a second, after its write)
//! vouches for nothing: its module files are let through recorded High
//! (DKMS's directories) or refused, as a write outside a transaction.
//!
//! The lab (ubuntu2604) met that residual on one plain `dpkg -i` in four.
//! Since, the kernel reads the lock at the write: `module_lock_observe`
//! (`file_lock`) keeps the package managers' write locks on the files of
//! [`lock_keys`] (`MODULE_PKG_LOCKERS`), and the write history names a
//! transaction only when its package manager holds one. This sampling is
//! the fallback for a start whose lock observer did not attach (the
//! controller then tells the kernel, `conf_slot::LOCKS_UNOBSERVED`).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use common::module_judge::Txn;

/// The package managers' lock files: dpkg's (and apt's front end), rpm's.
pub const LOCK_FILES: &[&str] = &[
    "/var/lib/dpkg/lock-frontend",
    "/var/lib/dpkg/lock",
    "/var/lib/rpm/.rpm.lock",
    "/usr/lib/sysimage/rpm/.rpm.lock",
];

/// Lot 370 (the lab): the lock files present, by the inode the kernel's
/// `file_lock` hook sees (root's, not writable by others), each with its
/// bit (`MODULE_PKG_LOCKS`).
pub fn lock_keys() -> Vec<(common::wire::InodeKey, u32)> {
    LOCK_FILES
        .iter()
        .enumerate()
        .filter_map(|(i, p)| {
            crate::execpol::kernel::trusted_image_key(std::path::Path::new(p)).map(|k| {
                (
                    common::wire::InodeKey {
                        dev: k.dev,
                        ino: k.ino,
                    },
                    1u32 << i,
                )
            })
        })
        .collect()
}

/// How long a transaction seen alive is remembered: long enough for the
/// look after its last write.
pub const KEEP: Duration = Duration::from_secs(3600);

/// The most transactions remembered.
pub const SEEN_MAX: usize = 1024;

/// The pids `/proc/locks` (`locks`) shows holding a lock on an inode
/// numbered in `inodes`: POSIX and BSD locks; an OFD lock (no pid) and a
/// waiter (`->`) hold nothing here.
pub fn holders(locks: &str, inodes: &[u64]) -> Vec<u32> {
    let mut out = Vec::new();
    for line in locks.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.get(1) == Some(&"->") || f.len() < 6 {
            continue;
        }
        let (Ok(pid), Some(ino)) = (
            f[4].parse::<i64>(),
            f[5].rsplit(':').next().and_then(|i| i.parse::<u64>().ok()),
        ) else {
            continue;
        };
        if pid > 1 && inodes.contains(&ino) && !out.contains(&(pid as u32)) {
            out.push(pid as u32);
        }
    }
    out
}

/// A `/proc/<pid>/stat` text's state letter and start (ticks since boot).
pub fn state_and_start(stat: &str) -> Option<(char, u64)> {
    let rest = &stat[stat.rfind(')')? + 1..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    let state = f.first()?.chars().next()?;
    // field 22 (starttime) is the 20th after the name
    let start = f.get(19)?.parse().ok()?;
    Some((state, start))
}

/// A process in this state holds a live transaction: not stopped (`T`), not
/// stopped under a tracer (`t`), not a zombie or dead.
pub fn running(state: char) -> bool {
    !matches!(state, 'T' | 't' | 'Z' | 'X' | 'x')
}

/// The transactions seen alive: `(tgid, start in ticks)` → when last seen.
#[derive(Debug, Default)]
pub struct Txns {
    seen: HashMap<(u32, u64), Instant>,
}

impl Txns {
    /// One sample of the host: the lock files' holders, each running.
    pub fn sample(&mut self) {
        use std::os::unix::fs::MetadataExt;
        let inodes: Vec<u64> = LOCK_FILES
            .iter()
            .filter_map(|p| antitamper_bpf::kernel_roots::symlink_metadata(p).ok())
            .map(|m| m.ino())
            .collect();
        if inodes.is_empty() {
            return;
        }
        let Ok(locks) = nn_linux::state_read::read_state("/proc/locks") else {
            return;
        };
        self.sample_with(
            &locks,
            &inodes,
            |pid| nn_linux::state_read::read_state(format!("/proc/{pid}/stat")).ok(),
            Instant::now(),
        );
    }

    /// [`Self::sample`] of the texts given (`stat_of`: a pid's stat).
    pub fn sample_with(
        &mut self,
        locks: &str,
        inodes: &[u64],
        stat_of: impl Fn(u32) -> Option<String>,
        now: Instant,
    ) {
        for pid in holders(locks, inodes) {
            let Some((state, start)) = stat_of(pid).as_deref().and_then(state_and_start) else {
                continue;
            };
            if running(state) {
                if self.seen.len() >= SEEN_MAX && !self.seen.contains_key(&(pid, start)) {
                    self.forget(now, Duration::ZERO);
                }
                self.seen.insert((pid, start), now);
            }
        }
        self.forget(now, KEEP);
    }

    /// Forget what was last seen more than `keep` before `now` (all of it
    /// past the cap).
    fn forget(&mut self, now: Instant, keep: Duration) {
        self.seen
            .retain(|_, at| now.saturating_duration_since(*at) < keep);
    }

    /// Transaction `t` (the kernel's start in nanoseconds, `tick_ns` a
    /// tick's) was seen holding a package manager's lock, running.
    pub fn live(&self, t: Txn, tick_ns: u64) -> bool {
        self.seen.contains_key(&(t.tgid, t.start / tick_ns.max(1)))
    }
}

/// Nanoseconds in a clock tick (`/proc/<pid>/stat`'s unit).
pub fn tick_ns() -> u64 {
    // SAFETY: sysconf has no preconditions.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    1_000_000_000 / if hz > 0 { hz as u64 } else { 100 }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCKS: &str = "\
1: POSIX  ADVISORY  WRITE 4242 fd:01:131074 0 EOF
1: -> POSIX  ADVISORY  WRITE 4300 fd:01:131074 0 EOF
2: OFDLCK ADVISORY  WRITE -1 fd:01:131075 0 EOF
3: FLOCK  ADVISORY  WRITE 777 00:19:12 0 EOF
4: POSIX  ADVISORY  WRITE 5151 00:2e:131075 0 EOF
";

    fn stat(state: char, start: u64) -> String {
        format!(
            "4242 (dpkg (x)) {state} 1 4242 4242 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {start} 1 1"
        )
    }

    /// Lot 370 (F10-2): the lock files' holders — a waiter, an OFD lock and
    /// a lock on another file hold nothing here; a btrfs device in
    /// `/proc/locks` that `stat` does not show still matches by inode.
    #[test]
    fn the_holders_of_a_package_managers_lock() {
        assert_eq!(holders(LOCKS, &[131_074]), vec![4242]);
        assert_eq!(holders(LOCKS, &[131_074, 131_075]), vec![4242, 5151]);
        assert!(holders(LOCKS, &[999]).is_empty());
        assert_eq!(state_and_start(&stat('S', 8_812)), Some(('S', 8_812)));
        assert!(running('S') && running('R') && running('D'));
        assert!(!running('T') && !running('t') && !running('Z'));
    }

    /// Lot 370 (F10-2): a transaction is live when its package manager was
    /// seen holding the lock, running — by its thread group and start; a
    /// stopped holder, another start (a reused pid) or no lock is none.
    #[test]
    fn a_transaction_is_live_only_seen_holding_its_lock_running() {
        let tick = 10_000_000;
        let now = Instant::now();
        let txn = Txn {
            tgid: 4242,
            start: 8_812 * tick + 3_000_000,
        };
        let mut t = Txns::default();
        t.sample_with(LOCKS, &[131_074], |_| Some(stat('T', 8_812)), now);
        assert!(!t.live(txn, tick), "stopped: no transaction");
        t.sample_with(LOCKS, &[131_074], |_| Some(stat('S', 8_812)), now);
        assert!(t.live(txn, tick));
        assert!(
            !t.live(
                Txn {
                    start: 9_000 * tick,
                    ..txn
                },
                tick
            ),
            "another start"
        );
        assert!(!t.live(Txn { tgid: 4300, ..txn }, tick), "a waiter");
        // remembered for KEEP, then forgotten
        t.sample_with("", &[131_074], |_| None, now + KEEP / 2);
        assert!(t.live(txn, tick));
        t.sample_with("", &[131_074], |_| None, now + KEEP);
        assert!(!t.live(txn, tick));
        // no lock held: nothing
        let mut t = Txns::default();
        t.sample_with(LOCKS, &[999], |_| Some(stat('S', 8_812)), now);
        assert!(!t.live(txn, tick));
    }
}
