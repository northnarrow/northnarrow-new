//! Lot 277: the processes not started in the cgroup they run in — the
//! kernel's half of the per-rule policy's exemptions by cgroup or unit,
//! shared by the eBPF programs (`agent-ebpf/src/cgroup_join.rs`) and the
//! agent (`nn_linux::cgroup_join`). `no_std`, like [`crate::cgroup_limits`].
//!
//! An exemption by cgroup (`exempt <rule> cgroup /system.slice/x.service`)
//! or by unit (`exempt <rule> unit x.service`) holds only for a process
//! started in that cgroup: spawned into it by systemd (PID 1), or forked
//! from a process that was. A root that writes its own pid into an exempt
//! service's `cgroup.procs`, or starts a child there with
//! `clone3(CLONE_INTO_CGROUP)`, is not that service. The eBPF programs
//! mark such a process — by its thread-group id, with its leader's start
//! time — at the move or the birth, every process it forks after it, and
//! drop the mark when its last thread exits; an exemption by cgroup or
//! unit is never applied to a marked process. A move into a cgroup an
//! exemption names is signed ([`crate::wire::FS_OP_CGROUP_JOIN`]).
//!
//! What counts as systemd's placement ([`placement`]): a move PID 1 makes
//! (a unit's process placed at its start, a scope's, a process systemd
//! was asked to attach), and the move a child of PID 1 makes of itself
//! before it ran any program of its own (systemd up to 254 forks, the
//! child moves itself, then executes the unit's command). A move that
//! changes nothing is no move ([`noop`]): the moved task is the writing
//! thread itself and its cgroup did not change — systemd 255's executor
//! moving itself after PID 1 did (255 spawns it, then PID 1 attaches it),
//! or 256+'s after `CLONE_INTO_CGROUP`. Everything else marks — a move of
//! another thread of the writer's own process included (the review of
//! #494, B1: a second thread putting its leader into a threaded child
//! named like an exempt unit).
//!
//! A mark the kernel cannot take (an allocation failed) is never a silent
//! loss and never a host-wide one (the review of #494, D2): the thread
//! group's byte is set in the preallocated `CGROUP_JOIN_LOST`
//! ([`lost_slot`]), passed on at a fork like a mark and cleared at its
//! tgid's next fork — that process tree, and only it, is "not known", and
//! refused an exemption by cgroup or unit. One byte a tgid, written with a
//! plain store of 1 or 0 (the re-review of #494, R1: a bit set by a test
//! and an add could be added twice by two CPUs, which left the group's bit
//! clear and carried into its neighbour's).
//!
//! The tracker's maps and links are pinned in a directory of their own,
//! next to the agent's pin root and not in it ([`pin_dir`]): an upgrade's
//! purge of the pin root leaves the marks and the programs (the re-review
//! of #494, R2). Its name carries the maps' schema ([`PIN_SCHEMA`]) and a
//! generation, never their size (the third review of #494, R2-a: a size in
//! the name made a `sysctl` before a restart a reset, and a reset gave the
//! marked back their exemption). A start adopts only the directory the
//! previous start of this boot registered, its maps the ids it registered
//! in the layout of this schema (R2-b); anything else is a reset — new
//! maps in the next generation's directory, every process started before
//! them "not known" ([`EPOCH_SLOTS`]), signed — never a silent loss.

/// The marks the object declares (the agent sizes the map at its load to
/// the host's `kernel.pid_max` and `kernel.threads-max`, the lower:
/// [`joined_entries`]). The map allocates an entry at each mark
/// (`BPF_F_NO_PREALLOC`): no more thread groups can be alive than tasks.
pub const JOINED_ENTRIES: u32 = 32768;

/// `PID_MAX_LIMIT` on 64-bit (include/linux/threads.h): no tgid reaches it.
pub const PID_LIMIT: u32 = 4 * 1024 * 1024;

/// The bytes of one entry of `CGROUP_JOIN_LOST`.
pub const LOST_BYTES: usize = 64;

/// The entries of `CGROUP_JOIN_LOST`: one byte per possible tgid (4 MiB).
pub const LOST_SLOTS: u32 = PID_LIMIT / LOST_BYTES as u32;

/// The layout of the tracker's pinned maps (key, value, kind and flags of
/// `CGROUP_JOINED`, `CGROUP_JOIN_LOST`, `CGROUP_JOIN_STATS`,
/// `CGROUP_JOIN_EPOCH`): raised with any change to one of them, so that a
/// start never adopts maps of another layout. Not their size: the marks'
/// entries are a capacity fixed when the map is made (the third review of
/// #494, R2-a).
pub const PIN_SCHEMA: u32 = 1;

/// The name's part before the schema of the tracker's pin directory:
/// `<pin root><PIN_DIR_INFIX><schema>_<generation>` — no dot: bpffs refuses
/// a name with one (`bpf_lookup`, v5.15 and v6.8 `kernel/bpf/inode.c`:
/// "dots in names … are reserved", EPERM; lot 277's lab).
pub const PIN_DIR_INFIX: &str = "-cgroup-join-v";

/// `CGROUP_JOIN_EPOCH`: `[CLOCK_MONOTONIC ns, CLOCK_BOOTTIME ns]` of the
/// last reset of the marks this boot, 0 when none. A process started before
/// it is "not known" — the agent compares its start (`/proc/<pid>/stat`,
/// boot time), the kernel a forking parent's leader's start (monotonic)
/// and passes "not known" on to the child — so that a reset, whatever made
/// it, gives no marked process back its exemption (the third review of
/// #494, R2-a). PID 1's own forks are systemd's placement and pass nothing.
pub const EPOCH_SLOTS: u32 = 2;

/// The tracker's pin directory for pin root `root`, generation `gen`:
/// `/sys/fs/bpf/northnarrow-cgroup-join-v1_0`. A sibling of the root, so a
/// purge of the root leaves it.
#[cfg(feature = "std")]
pub fn pin_dir(root: &str, gen: u32) -> String {
    format!("{root}{PIN_DIR_INFIX}{PIN_SCHEMA}_{gen}")
}

/// `name` (a file name in the root's parent) as a tracker pin directory of
/// pin root `root_name`: its schema and generation — the size-named form of
/// a build before the third review (`v1-63222`) is one too, generation
/// `None`.
pub fn parse_pin_dir(root_name: &str, name: &str) -> Option<(u32, Option<u32>)> {
    let rest = name.strip_prefix(root_name)?.strip_prefix(PIN_DIR_INFIX)?;
    let num = |v: &str| {
        (!v.is_empty() && v.len() <= 10 && v.bytes().all(|b| b.is_ascii_digit()))
            .then(|| v.parse::<u32>().ok())
            .flatten()
    };
    if let Some((schema, gen)) = rest.split_once('_') {
        return Some((num(schema)?, Some(num(gen)?)));
    }
    let (schema, size) = rest.split_once('-')?;
    num(size)?;
    Some((num(schema)?, None))
}

/// `name` is a tracker pin directory of pin root `root_name`, whatever its
/// layout or generation.
pub fn is_pin_dir_of(root_name: &str, name: &str) -> bool {
    parse_pin_dir(root_name, name).is_some()
}

/// Lot 277 (the review of #494, D2): the entries the agent gives the marks
/// at its load — the host's `pid_max` and `threads-max`, the lower (a fork
/// past `threads-max` fails, so no more groups can be alive), within
/// [`JOINED_ENTRIES`] and [`PID_LIMIT`]. A host that raises either later
/// can mark more groups than the map holds: those are set in the bitmap
/// (not known), never lost.
pub fn joined_entries(pid_max: Option<u64>, threads_max: Option<u64>) -> u32 {
    let n = match (pid_max, threads_max) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) | (None, Some(a)) => a,
        (None, None) => u64::from(PID_LIMIT),
    };
    n.clamp(u64::from(JOINED_ENTRIES), u64::from(PID_LIMIT)) as u32
}

/// The entry and the byte of `tgid` in `CGROUP_JOIN_LOST`, `None` past it
/// (no tgid is).
pub const fn lost_slot(tgid: u32) -> Option<(u32, usize)> {
    if tgid >= PID_LIMIT {
        return None;
    }
    Some((
        tgid / LOST_BYTES as u32,
        (tgid % LOST_BYTES as u32) as usize,
    ))
}

/// Lot 277 (the review of #494, B1): a completed move changed nothing — the
/// moved task is the writing thread itself (`moved_is_current`), whose
/// cgroup before the move (`src_id`, recorded for this write: `src_this_write`)
/// is its cgroup now (`now_id`). A move of another thread of the same
/// process is a move, whatever the writer's own cgroup.
pub const fn noop(moved_is_current: bool, src_this_write: bool, src_id: u64, now_id: u64) -> bool {
    moved_is_current && src_this_write && src_id == now_id
}

/// What `bpf_probe_read_kernel_str` gave of a destination path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRead {
    /// Nothing read.
    Unread,
    /// The buffer filled ([`PATH_READ`] bytes, the last its NUL): the path
    /// may go on — signed without a name while an exemption is in force.
    Cut,
    /// The whole path, its NUL inside the buffer.
    Whole,
}

/// The review of #494, D1: the helper returns the bytes copied, the NUL
/// included, and at a full buffer writes the NUL in its last byte and
/// returns the buffer's size — so a full buffer is the cut, not its last
/// byte.
pub const fn path_read(n: i64) -> PathRead {
    if n <= 0 {
        PathRead::Unread
    } else if n as u64 >= PATH_READ as u64 {
        PathRead::Cut
    } else {
        PathRead::Whole
    }
}

/// The exemption names the kernel matches a move's destination against
/// (the per-rule policy's cgroup paths and unit names, hashed).
pub const EXEMPT_NAMES_ENTRIES: u32 = 1024;

/// Slots of the statistics array (`CGROUP_JOIN_STATS`, pinned).
/// Marks the kernel could not take (those groups are in the bitmap: not
/// known), counted.
pub const STAT_LOST: u32 = 0;
/// Marks made at a move or a birth (the roots of marked trees).
pub const STAT_ROOTS: u32 = 1;
/// Marks a fork passed on.
pub const STAT_INHERITED: u32 = 2;
/// Moves into a cgroup an exemption names (each one signed, rate-limited).
pub const STAT_INTO_EXEMPT: u32 = 3;
/// The slots.
pub const STAT_SLOTS: u32 = 4;

/// How a process came to be marked (the value's byte 4).
pub const HOW_MOVED: u8 = 1;
/// Started by `clone3(CLONE_INTO_CGROUP)` by a process other than PID 1.
pub const HOW_BORN_INTO: u8 = 2;
/// Forked from a marked process.
pub const HOW_INHERITED: u8 = 3;

/// `CLONE_INTO_CGROUP` (include/uapi/linux/sched.h, 5.7+).
pub const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

/// Kinds of [`EXEMPT_NAMES`](EXEMPT_NAMES_ENTRIES) keys.
pub const NAME_CGROUP: u8 = 1;
/// A unit's name (`backup.service`).
pub const NAME_UNIT: u8 = 2;

/// The bytes of a destination path the kernel reads, its NUL included; a
/// path of `PATH_READ - 1` bytes or more is signed with a hash of 0 while
/// any exemption is in force (it may name one the hash could not see:
/// [`path_read`]).
pub const PATH_READ: usize = 256;

/// The mark's second word: who made it (the writer's or the forker's
/// tgid) and how.
pub const fn pack(how: u8, by_tgid: u32) -> u64 {
    ((how as u64) << 32) | by_tgid as u64
}

/// [`pack`]'s inverse: `(how, by_tgid)`.
pub const fn unpack(info: u64) -> (u8, u32) {
    ((info >> 32) as u8, info as u32)
}

/// What a completed move of a thread group is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Move {
    /// systemd's placement: no mark.
    Placement,
    /// The process was already in the destination: no move.
    NoOp,
    /// A move into the cgroup by anyone else: the tree is marked.
    Mark,
}

/// Lot 277: classify a completed move of thread group `moved_tgid` by
/// `writer_tgid` (the thread that wrote `cgroup.procs`). `moved_parent` is
/// the moved process's real parent's tgid, `pre_exec` whether it still
/// runs its parent's image (`mm->exe_file` the same file: it executed
/// nothing since the fork), `unchanged` whether it was in the destination
/// already (a self-move whose source and destination ids are equal).
pub const fn placement(
    writer_tgid: u32,
    moved_tgid: u32,
    moved_parent: u32,
    pre_exec: bool,
    unchanged: bool,
) -> Move {
    if unchanged {
        return Move::NoOp;
    }
    if writer_tgid == 1 {
        return Move::Placement;
    }
    if writer_tgid == moved_tgid && moved_parent == 1 && pre_exec {
        return Move::Placement;
    }
    Move::Mark
}

/// FNV-1a, 64 bits: the offset basis.
pub const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a, 64 bits: the prime.
pub const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// One byte into an FNV-1a hash.
#[inline(always)]
pub const fn fnv_step(h: u64, b: u8) -> u64 {
    (h ^ b as u64).wrapping_mul(FNV_PRIME)
}

/// FNV-1a of `bytes` (the agent's side: the policy's names).
pub const fn fnv(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    let mut i = 0;
    while i < bytes.len() {
        h = fnv_step(h, bytes[i]);
        i += 1;
    }
    h
}

/// Lot 277: the walk the eBPF program makes over a move's destination
/// path, one byte at a time, as a pure function: the hash of the whole path
/// (an exemption by `cgroup` names it) and of each `/`-separated component
/// (an exemption by `unit` names one), each looked up in `kinds` (the
/// policy's names: `NAME_CGROUP` / `NAME_UNIT` bits, 0 for none). The match
/// is the whole path with `NAME_CGROUP`, else the last component with
/// `NAME_UNIT`. A component is any of them, not only the last unit of the
/// path `unit_of` names (`nn_core::decision::rule_policy`): a move into a
/// cgroup below an exempt unit is signed too — a wider record, never a
/// missing one (the mark is made whatever the destination). The eBPF loop
/// keeps no counter, so the 5.15 verifier's states stay few.
pub fn match_destination(path: &[u8], kinds: impl Fn(u64) -> u8) -> Option<u64> {
    let mut full = FNV_OFFSET;
    let mut comp = FNV_OFFSET;
    let mut hit = 0u64;
    for &b in path {
        full = fnv_step(full, b);
        if b == b'/' {
            if kinds(comp) & NAME_UNIT != 0 {
                hit = comp;
            }
            comp = FNV_OFFSET;
        } else {
            comp = fnv_step(comp, b);
        }
    }
    if kinds(comp) & NAME_UNIT != 0 {
        hit = comp;
    }
    if kinds(full) & NAME_CGROUP != 0 {
        return Some(full);
    }
    (hit != 0).then_some(hit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_destination_matches_a_path_or_a_unit_component() {
        let names = [
            (fnv(b"/system.slice/backup.service"), NAME_CGROUP),
            (fnv(b"backup.service"), NAME_UNIT),
            (fnv(b"x.scope"), NAME_UNIT | NAME_CGROUP),
        ];
        let kinds = |h: u64| {
            names
                .iter()
                .filter(|(k, _)| *k == h)
                .fold(0u8, |a, (_, v)| a | v)
        };
        let m = |p: &[u8]| match_destination(p, kinds);
        // the whole path first, a cgroup exemption's
        assert_eq!(
            m(b"/system.slice/backup.service"),
            Some(fnv(b"/system.slice/backup.service"))
        );
        // a unit anywhere, the last one matched
        assert_eq!(
            m(b"/user.slice/user-1000.slice/user@1000.service/app.slice/backup.service"),
            Some(fnv(b"backup.service"))
        );
        assert_eq!(
            m(b"/system.slice/backup.service/sub"),
            Some(fnv(b"backup.service"))
        );
        assert_eq!(m(b"/a/backup.service/x.scope"), Some(fnv(b"x.scope")));
        assert_eq!(
            m(b"/a/x.scope/backup.service"),
            Some(fnv(b"backup.service"))
        );
        // a path's hash only names a cgroup exemption, a component's only a
        // unit's: `/x.scope` is a path no cgroup exemption gives, and its
        // component is a unit
        assert_eq!(m(b"/x.scope"), Some(fnv(b"x.scope")));
        // nothing named
        assert_eq!(m(b"/system.slice/other.service"), None);
        assert_eq!(m(b"/system.slice"), None);
        assert_eq!(m(b"/"), None);
        assert_eq!(m(b"backup.services"), None);
        // the empty components hash to the offset basis, which no name has
        assert_eq!(fnv(b""), FNV_OFFSET);
    }

    #[test]
    fn only_systemd_places_and_a_noop_is_no_move() {
        // PID 1 moves anything (a unit's process, a scope's)
        assert_eq!(placement(1, 4242, 77, false, false), Move::Placement);
        // systemd's child moves itself before its exec
        assert_eq!(placement(4242, 4242, 1, true, false), Move::Placement);
        // ... not after it, not another process, not an orphan's child
        assert_eq!(placement(4242, 4242, 1, false, false), Move::Mark);
        assert_eq!(placement(4242, 4343, 1, true, false), Move::Mark);
        assert_eq!(placement(4242, 4242, 900, true, false), Move::Mark);
        // a root shell moving itself
        assert_eq!(placement(4242, 4242, 4000, false, false), Move::Mark);
        // already there: no move, whoever writes
        assert_eq!(placement(4242, 4242, 4000, false, true), Move::NoOp);
    }

    /// The review of #494, B1: no move only for the writing thread moving
    /// itself to where it is; another thread of its process moved (a
    /// leader written into a threaded child's `cgroup.threads`) is a move,
    /// though the writer stays where it was.
    #[test]
    fn a_noop_is_the_writing_thread_staying_where_it_is() {
        assert!(noop(true, true, 7, 7));
        assert!(!noop(true, true, 7, 8), "the thread moved");
        assert!(
            !noop(false, true, 7, 7),
            "another thread moved, the writer stayed"
        );
        assert!(
            !noop(true, false, 7, 7),
            "no source recorded for this write"
        );
        // and the decision then marks the threaded move of the leader
        assert_eq!(
            placement(4242, 4242, 4000, false, noop(false, true, 7, 7)),
            Move::Mark
        );
    }

    /// The review of #494, D1: a full buffer is a cut path, whatever its
    /// last byte holds (the helper writes the NUL there).
    #[test]
    fn a_full_buffer_is_a_cut_path() {
        assert_eq!(path_read(0), PathRead::Unread);
        assert_eq!(path_read(-14), PathRead::Unread);
        assert_eq!(path_read(1), PathRead::Whole);
        assert_eq!(path_read(PATH_READ as i64 - 1), PathRead::Whole);
        assert_eq!(path_read(PATH_READ as i64), PathRead::Cut);
    }

    /// The review of #494, D2: the marks sized from the host, one bitmap bit
    /// for every possible tgid.
    #[test]
    fn the_marks_are_sized_from_the_host_and_every_tgid_has_a_bit() {
        assert_eq!(joined_entries(Some(4_194_304), Some(62_000)), 62_000);
        assert_eq!(joined_entries(Some(32_768), Some(1_000_000)), 32_768);
        assert_eq!(joined_entries(Some(1_000), Some(500)), JOINED_ENTRIES);
        assert_eq!(joined_entries(None, None), PID_LIMIT);
        assert_eq!(joined_entries(Some(u64::MAX), None), PID_LIMIT);
        assert_eq!(lost_slot(0), Some((0, 0)));
        assert_eq!(lost_slot(63), Some((0, 63)));
        assert_eq!(lost_slot(65), Some((1, 1)));
        assert_eq!(lost_slot(PID_LIMIT - 1), Some((LOST_SLOTS - 1, 63)));
        assert_eq!(lost_slot(PID_LIMIT), None);
        assert_eq!(LOST_SLOTS as usize * LOST_BYTES, PID_LIMIT as usize);
        // every tgid its own byte
        let mut seen = std::collections::HashSet::new();
        for t in (0..PID_LIMIT).step_by(4093).chain([1, 64, 4095, 4096]) {
            assert!(seen.insert(lost_slot(t).unwrap()), "{t}");
        }
    }

    /// The re-review of #494, R2, and the third review, R2-a: the tracker's
    /// pins beside the pin root, named by schema and generation, never by
    /// size; the size-named directories of before are found too.
    #[test]
    fn the_tracker_pins_are_named_by_schema_and_generation_beside_the_root() {
        assert_eq!(
            pin_dir("/sys/fs/bpf/northnarrow", 0),
            format!("/sys/fs/bpf/northnarrow-cgroup-join-v{PIN_SCHEMA}_0")
        );
        assert!(!pin_dir("/sys/fs/bpf/northnarrow", 3).starts_with("/sys/fs/bpf/northnarrow/"));
        // bpffs refuses a name with a dot (EPERM)
        assert!(!pin_dir("/sys/fs/bpf/northnarrow", 7)
            .rsplit('/')
            .next()
            .unwrap()
            .contains('.'));
        for (name, want) in [
            ("northnarrow-cgroup-join-v1_0", (1, Some(0))),
            ("northnarrow-cgroup-join-v2_17", (2, Some(17))),
            ("northnarrow-cgroup-join-v1-63222", (1, None)),
            ("northnarrow-cgroup-join-v0-4194304", (0, None)),
        ] {
            assert_eq!(parse_pin_dir("northnarrow", name), Some(want), "{name}");
            assert!(is_pin_dir_of("northnarrow", name), "{name}");
        }
        for no in [
            "northnarrow",
            "northnarrow-cgroup-join-v1",
            "northnarrow-cgroup-join-v1_",
            "northnarrow-cgroup-join-v1.0",
            "northnarrow-cgroup-join-v1-",
            "northnarrow-cgroup-join-v_1",
            "northnarrow-cgroup-join-vx_0",
            "northnarrow-cgroup-join-v1_0x",
            "northnarrow-cgroup-join-v1-64x",
            "northnarrow-cgroup-join-v1_99999999999",
            "other-cgroup-join-v1_0",
            "northnarrowx-cgroup-join-v1_0",
        ] {
            assert!(!is_pin_dir_of("northnarrow", no), "{no}");
        }
    }

    #[test]
    fn the_mark_packs_how_and_by_whom() {
        for (how, by) in [
            (HOW_MOVED, 1),
            (HOW_BORN_INTO, u32::MAX),
            (HOW_INHERITED, 4242),
        ] {
            assert_eq!(unpack(pack(how, by)), (how, by));
        }
    }
}
