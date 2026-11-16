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
//!   `systemd-executor` identities are), AND it runs in the cgroup of
//!   `systemd-journald.service` or of the namespace instance the agent's
//!   units log to (`systemd-journald@northnarrow.service`,
//!   `LogNamespace=northnarrow`: the reader of every line the agent
//!   writes). Root running that binary in one of those cgroups loses only
//!   the record, never the refusal; nothing else is exempt (PID 1, logind,
//!   polkit: no read of theirs was measured);
//! - every other caller is recorded once an hour per caller IMAGE and
//!   target ([`seen_key`], [`DEDUP_NS`]), not per process: a periodic
//!   reader is one record an hour, a short-lived tool at most 24 a day, and
//!   an image never seen before (`nsenter`, a tool of one's own) at its
//!   first use.
//!
//! Lot 359 (the re-check 3 of #567, three P3s):
//! - (a) journald is quiet only while its lot 277/281 marks are clean
//!   (`cgroup_join::clean`: not moved into its unit's cgroup, no
//!   code-injection access to it given to another) — root's copy of the
//!   image written into journald's `cgroup.procs`, or an `LD_PRELOAD`ed
//!   journald under a debugger, is recorded;
//! - (b) the dedup's key carries the caller's cgroup: an interpreter
//!   (`python3`) is one image for every program it runs, and a collector's
//!   record no longer silences another program's probe of the same target
//!   for the hour;
//! - (c) a record is "seen" only once the records' budget let it through
//!   ([`admit`]): a flood of minor denials on the same CPU took the budget,
//!   dropped the first record, and still marked it seen for an hour.

/// One record per caller image and target in this time (1 h).
pub const DEDUP_NS: u64 = 3_600_000_000_000;

/// The dedup's key: the caller's image (the device in the kernel's form
/// and the inode of `mm->exe_file`, `(0, 0)` for a task without one), the
/// target's tgid and (lot 359, P3 b) the caller's cgroup id —
/// `[ino, dev << 32 | tgid, cgroup]` (a kernel device is 32 bits, a tgid
/// below 2^22): exact, no hash.
pub const fn seen_key(exe_dev: u64, exe_ino: u64, target_tgid: u32, cgroup: u64) -> [u64; 3] {
    [
        exe_ino,
        (exe_dev & 0xffff_ffff) << 32 | target_tgid as u64,
        cgroup,
    ]
}

/// The key of the kernel's journald identities (`PTRACE_READ_QUIET`): an
/// image (the device in the kernel's form, the inode) in a cgroup (its id).
pub const fn quiet_key(exe_dev: u64, exe_ino: u64, cgroup: u64) -> [u64; 3] {
    [exe_dev, exe_ino, cgroup]
}

/// The caller is the packaged journald in its unit: its image in its
/// cgroup is one of journald's identities (`journald`: whether the map
/// holds that [`quiet_key`]) — and (lot 359, P3 a) its lot 277/281 marks
/// are clean (`marks_clean`, asked only of journald's identity). A cgroup
/// id of 0 (none read: a cgroup v1 host) is never asked.
#[inline(always)]
pub fn quiet(
    exe_dev: u64,
    exe_ino: u64,
    cgroup: u64,
    journald: impl FnOnce(&[u64; 3]) -> bool,
    marks_clean: impl FnOnce() -> bool,
) -> bool {
    cgroup != 0 && journald(&quiet_key(exe_dev, exe_ino, cgroup)) && marks_clean()
}

/// A record is due: none for this key yet, or the last at least
/// [`DEDUP_NS`] ago.
pub const fn due(last: Option<u64>, now: u64) -> bool {
    match last {
        None => true,
        Some(l) => now.wrapping_sub(l) >= DEDUP_NS,
    }
}

/// Lot 359 (P3 c): the record is written — due ([`due`]), then the
/// records' budget asked (`budget`, which takes its room) — and only then
/// is its key marked seen: a record the budget drops leaves the key as it
/// was, and the next refusal is recorded.
#[inline(always)]
pub fn admit(last: Option<u64>, now: u64, budget: impl FnOnce() -> bool) -> bool {
    due(last, now) && budget()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// The eBPF record's steps, on a host's day: the quiet check, then the
    /// dedup by image and target.
    struct Kernel {
        journald: Vec<[u64; 3]>,
        seen: HashMap<[u64; 3], u64>,
        records: Vec<(u64, u64)>,
        /// Lot 359 (P3 a): the marks of the callers (by cgroup here) that
        /// are not clean.
        marked: Vec<u64>,
        /// Lot 359 (P3 c): the records' budget left (`None`: unbounded).
        budget: Option<usize>,
    }

    impl Kernel {
        fn new() -> Kernel {
            Kernel {
                journald: vec![
                    quiet_key(0x0080_0001, 4242, 77),
                    quiet_key(0x0080_0001, 4242, 78),
                ],
                seen: HashMap::new(),
                records: Vec::new(),
                marked: Vec::new(),
                budget: None,
            }
        }
        /// A refused read of `target` by a process running `exe` in
        /// `cgroup` at `now`, in the eBPF record's order.
        fn read(&mut self, exe: (u64, u64), cgroup: u64, target: u32, now: u64) {
            let marked = self.marked.contains(&cgroup);
            if quiet(
                exe.0,
                exe.1,
                cgroup,
                |k| self.journald.contains(k),
                || !marked,
            ) {
                return;
            }
            let k = seen_key(exe.0, exe.1, target, cgroup);
            let budget = &mut self.budget;
            let room = || match budget {
                None => true,
                Some(0) => false,
                Some(n) => {
                    *n -= 1;
                    true
                }
            };
            if !admit(self.seen.get(&k).copied(), now, room) {
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
            // the namespace instance the agent's units log to
            k.read(JOURNALD, 78, AGENT, now);
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
        let map = [quiet_key(1, 2, 77)];
        let held = |k: &[u64; 3]| map.contains(k);
        assert!(quiet(1, 2, 77, held, || true));
        assert!(
            !quiet(1, 2, 79, held, || true),
            "journald's image in another cgroup"
        );
        assert!(
            !quiet(1, 3, 77, held, || true),
            "another image in journald's cgroup"
        );
        assert!(!quiet(2, 2, 77, held, || true), "another device");
        let zero = [quiet_key(1, 2, 0)];
        assert!(
            !quiet(1, 2, 0, |k: &[u64; 3]| zero.contains(k), || true),
            "no cgroup id: never quiet"
        );
        let mut k = Kernel::new();
        k.read(JOURNALD, 500, AGENT, S);
        k.read(HTOP, 77, AGENT, S);
        assert_eq!(k.count(JOURNALD), 1);
        assert_eq!(k.count(HTOP), 1);
    }

    /// The key is exact: the image's device and inode, the target and
    /// (lot 359) the cgroup, no two of them alike.
    #[test]
    fn the_dedup_key_tells_images_and_targets_apart() {
        let k = seen_key(0x0080_0001, 4242, AGENT, 900);
        assert_ne!(k, seen_key(0x0080_0002, 4242, AGENT, 900));
        assert_ne!(k, seen_key(0x0080_0001, 4243, AGENT, 900));
        assert_ne!(k, seen_key(0x0080_0001, 4242, WATCHDOG, 900));
        assert_ne!(k, seen_key(0x0080_0001, 4242, AGENT, 901));
        assert_ne!(seen_key(0, 0, 1, 0), seen_key(0, 1, 0, 0));
        assert_eq!(
            seen_key(u64::MAX, 1, (1 << 22) - 1, 0)[1] & 0xffff_ffff,
            (1 << 22) - 1
        );
        assert!(due(None, 0));
        assert!(!due(Some(10), 10 + DEDUP_NS - 1));
        assert!(due(Some(10), 10 + DEDUP_NS));
        assert_eq!(DEDUP_NS, 3600 * 1_000_000_000);
    }

    /// Named test (lot 359, the re-check 3 of #567, P3 a): journald's image
    /// in its unit's cgroup is recorded once its lot 277/281 marks are not
    /// clean — root's process written into journald's cgroup, or journald
    /// with injection access given to another.
    #[test]
    fn journald_with_marks_that_are_not_clean_is_recorded() {
        let mut k = Kernel::new();
        k.read(JOURNALD, 77, AGENT, S);
        assert_eq!(k.count(JOURNALD), 0, "clean: quiet");
        k.marked.push(77);
        k.read(JOURNALD, 77, AGENT, 2 * S);
        assert_eq!(k.count(JOURNALD), 1, "moved in or injected: recorded");
        // the marks are asked of journald's identity only
        let map = [quiet_key(1, 2, 77)];
        let asked = std::cell::Cell::new(0);
        let marks = || {
            asked.set(asked.get() + 1);
            true
        };
        assert!(!quiet(1, 3, 77, |q| map.contains(q), marks));
        assert_eq!(asked.get(), 0);
        assert!(quiet(1, 2, 77, |q| map.contains(q), marks));
        assert_eq!(asked.get(), 1);
        assert!(!quiet(1, 2, 77, |q| map.contains(q), || false));
    }

    /// Named test (lot 359, P3 b): an interpreter is one image for every
    /// program it runs — a collector's record of the agent, made in its own
    /// unit's cgroup, does not silence an attacker's probe of the agent by
    /// the same interpreter from another cgroup within the hour.
    #[test]
    fn a_collectors_record_does_not_silence_another_programs_probe_of_the_same_image() {
        const PYTHON: (u64, u64) = (0x0080_0001, 8181);
        let mut k = Kernel::new();
        k.read(PYTHON, 900, AGENT, S); // the collector, in its unit
        k.read(PYTHON, 905, AGENT, 2 * S); // a probe, from a shell
        assert_eq!(k.count(PYTHON), 2);
        // the collector itself stays one an hour
        for t in 3..3600 {
            k.read(PYTHON, 900, AGENT, t * S);
        }
        assert_eq!(k.count(PYTHON), 2);
    }

    /// Named test (lot 359, P3 c): a record the budget drops is not "seen"
    /// — the next refusal of that image and target is recorded, not
    /// silenced for the hour.
    #[test]
    fn a_record_the_budget_drops_is_not_marked_seen() {
        let mut k = Kernel::new();
        k.budget = Some(0); // a flood of minor denials took this second's
        k.read(NSENTER, 902, AGENT, S);
        assert_eq!(k.count(NSENTER), 0, "dropped");
        assert!(k.seen.is_empty(), "and not marked seen");
        k.budget = Some(1);
        k.read(NSENTER, 902, AGENT, 2 * S);
        assert_eq!(k.count(NSENTER), 1, "the next one is recorded");
        k.read(NSENTER, 902, AGENT, 3 * S);
        assert_eq!(k.count(NSENTER), 1, "then the hour's dedup");
        // and the budget is asked only of a record that is due
        let asked = std::cell::Cell::new(false);
        assert!(!admit(Some(S), 2 * S, || {
            asked.set(true);
            true
        }));
        assert!(!asked.get());
    }
}
