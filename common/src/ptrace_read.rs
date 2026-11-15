//! The re-check 2 of #567 (point 2): when a refused read-mode ptrace access
//! of one of the agent's processes (`FS_OP_PTRACE_READ`: its
//! `/proc/<pid>/exe`, `ns/*`, `fd/`, `maps` …) is recorded. The refusal is
//! never in question here — every one stands; this is only its record.
//!
//! A record per caller process and target each minute (fix round 2) was
//! about 2,880 Low records a day from journald alone — it reads the
//! `/proc/<pid>/exe` of every client whose lines it takes — and as many
//! from each periodic reader (htop, a monitoring agent's process
//! collector), while a short-lived tool (`pidof`, `lsof`, `ss -p`) is a new
//! process at each run and was recorded at each: rows that bury the one
//! that matters (`nsenter -t <agent> -m`). Now:
//!
//! - the packaged `systemd-journald`, in its own unit's cgroup, is not
//!   recorded ([`quiet`]): its image is the file at its install path that
//!   root owns, in a directory only root may write, that the package
//!   database does not disown (read again every 10 s, as lot 310's
//!   `systemd-executor` identities are), AND it runs in
//!   `systemd-journald.service`'s cgroup. Root running that binary in that
//!   cgroup loses only the record, never the refusal; nothing else is
//!   exempt (PID 1, logind, polkit: no read of theirs was measured);
//! - every other caller is recorded once an hour per caller IMAGE and
//!   target ([`seen_key`], [`DEDUP_NS`]), not per process: a periodic
//!   reader is one record an hour, a short-lived tool at most 24 a day, and
//!   an image never seen before (`nsenter`, a tool of one's own) at its
//!   first use.

/// One record per caller image and target in this time (1 h).
pub const DEDUP_NS: u64 = 3_600_000_000_000;

/// The dedup's key: the caller's image (the device in the kernel's form
/// and the inode of `mm->exe_file`, `(0, 0)` for a task without one) and
/// the target's tgid — `[ino, dev << 32 | tgid]` (a kernel device is 32
/// bits, a tgid below 2^22): exact, no hash.
pub const fn seen_key(exe_dev: u64, exe_ino: u64, target_tgid: u32) -> [u64; 2] {
    [exe_ino, (exe_dev & 0xffff_ffff) << 32 | target_tgid as u64]
}

/// The caller is the packaged journald in its unit: its image is one of
/// journald's (`journald_cgroup`: the cgroup id written for that image,
/// `None` when it is none of them) and it runs in that cgroup. A cgroup id
/// of 0 (none read: a cgroup v1 host) never matches.
pub const fn quiet(journald_cgroup: Option<u64>, cgroup: u64) -> bool {
    match journald_cgroup {
        Some(c) => c != 0 && c == cgroup,
        None => false,
    }
}

/// A record is due: none for this key yet, or the last at least
/// [`DEDUP_NS`] ago.
pub const fn due(last: Option<u64>, now: u64) -> bool {
    match last {
        None => true,
        Some(l) => now.wrapping_sub(l) >= DEDUP_NS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// The eBPF record's steps, on a host's day: the quiet check, then the
    /// dedup by image and target.
    struct Kernel {
        journald: HashMap<(u64, u64), u64>,
        seen: HashMap<[u64; 2], u64>,
        records: Vec<(u64, u64)>,
    }

    impl Kernel {
        fn new() -> Kernel {
            Kernel {
                journald: HashMap::from([((0x0080_0001, 4242), 77)]),
                seen: HashMap::new(),
                records: Vec::new(),
            }
        }
        /// A refused read of `target` by a process running `exe` in
        /// `cgroup` at `now`.
        fn read(&mut self, exe: (u64, u64), cgroup: u64, target: u32, now: u64) {
            if quiet(self.journald.get(&exe).copied(), cgroup) {
                return;
            }
            let k = seen_key(exe.0, exe.1, target);
            if !due(self.seen.get(&k).copied(), now) {
                return;
            }
            self.seen.insert(k, now);
            self.records.push(exe);
        }
        fn count(&self, exe: (u64, u64)) -> usize {
            self.records.iter().filter(|e| **e == exe).count()
        }
    }

    const S: u64 = 1_000_000_000;
    const JOURNALD: (u64, u64) = (0x0080_0001, 4242);
    const HTOP: (u64, u64) = (0x0080_0001, 5151);
    const PIDOF: (u64, u64) = (0x0080_0001, 6161);
    const NSENTER: (u64, u64) = (0x0080_0001, 7171);
    const AGENT: u32 = 812;
    const WATCHDOG: u32 = 799;

    /// The re-check 2 of #567 (point 2), named: journald reading the
    /// agent's and the watchdog's `/proc/<pid>/exe` every round (each
    /// second, all day) gives no record; htop refreshing every 2 s gives at
    /// most one an hour per target; `pidof` run each minute (a new process
    /// each time) the same; `nsenter` is recorded at its first use.
    #[test]
    fn journald_reading_the_agent_every_round_gives_no_record_and_htop_one_an_hour() {
        let mut k = Kernel::new();
        let day = 24 * 3600;
        for t in 0..day {
            let now = 1_000 * S + t * S;
            k.read(JOURNALD, 77, AGENT, now);
            k.read(JOURNALD, 77, WATCHDOG, now);
            if t % 2 == 0 {
                k.read(HTOP, 900, AGENT, now);
            }
            if t % 60 == 0 {
                k.read(PIDOF, 901, AGENT, now);
            }
        }
        assert_eq!(k.count(JOURNALD), 0);
        assert_eq!(k.count(HTOP), 24, "one an hour");
        assert_eq!(k.count(PIDOF), 24, "by its image, not its process");
        k.read(NSENTER, 902, AGENT, 1_000 * S + day * S);
        assert_eq!(k.count(NSENTER), 1, "a new image: at its first use");
        // and within any hour, at most one per image and target
        let mut k = Kernel::new();
        for t in 0..3600 {
            k.read(HTOP, 900, AGENT, 5 * S + t * S);
        }
        assert_eq!(k.count(HTOP), 1);
        k.read(HTOP, 900, WATCHDOG, 5 * S);
        assert_eq!(k.count(HTOP), 2, "another target: its own record");
    }

    /// The exemption is the packaged image AND its unit's cgroup: journald's
    /// binary run elsewhere (root's copy in a shell's cgroup), another
    /// image in journald's cgroup, a cgroup v1 host (no id), are recorded.
    #[test]
    fn only_the_packaged_journald_in_its_unit_is_quiet() {
        assert!(quiet(Some(77), 77));
        assert!(!quiet(Some(77), 78), "journald's image in another cgroup");
        assert!(!quiet(None, 77), "another image in journald's cgroup");
        assert!(!quiet(Some(0), 0), "no cgroup id: never quiet");
        let mut k = Kernel::new();
        k.read(JOURNALD, 500, AGENT, S);
        k.read(HTOP, 77, AGENT, S);
        assert_eq!(k.count(JOURNALD), 1);
        assert_eq!(k.count(HTOP), 1);
    }

    /// The key is exact: the image's device and inode and the target, no
    /// two of them alike.
    #[test]
    fn the_dedup_key_tells_images_and_targets_apart() {
        let k = seen_key(0x0080_0001, 4242, AGENT);
        assert_ne!(k, seen_key(0x0080_0002, 4242, AGENT));
        assert_ne!(k, seen_key(0x0080_0001, 4243, AGENT));
        assert_ne!(k, seen_key(0x0080_0001, 4242, WATCHDOG));
        assert_ne!(seen_key(0, 0, 1), seen_key(0, 1, 0));
        assert_eq!(seen_key(u64::MAX, 1, (1 << 22) - 1)[1] & 0xffff_ffff, (1 << 22) - 1);
        assert!(due(None, 0));
        assert!(!due(Some(10), 10 + DEDUP_NS - 1));
        assert!(due(Some(10), 10 + DEDUP_NS));
        assert_eq!(DEDUP_NS, 3600 * 1_000_000_000);
    }
}
