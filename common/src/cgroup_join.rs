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
//! changes nothing (the process is already there: systemd 255's executor
//! moving itself after its parent did, or after `CLONE_INTO_CGROUP`) is no
//! move. Everything else marks.

/// The marked thread groups the map holds at most (a hash map that never
/// evicts: a mark it cannot take is counted, [`STAT_LOST`], and every
/// exemption by cgroup or unit is then refused until the agent restarts
/// on an empty map — never one mark lost in silence).
pub const JOINED_ENTRIES: u32 = 32768;

/// The exemption names the kernel matches a move's destination against
/// (the per-rule policy's cgroup paths and unit names, hashed).
pub const EXEMPT_NAMES_ENTRIES: u32 = 1024;

/// Slots of the statistics array (`CGROUP_JOIN_STATS`, pinned).
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

/// The bytes of a destination path the kernel hashes; a longer path is
/// signed with a hash of 0 when any exemption is in force (it may name one
/// the hash could not see).
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
