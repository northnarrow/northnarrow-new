//! Restore: what to do with each journaled file, and doing it.
//!
//! The rules ([`decide`]) are pure. A restore does not overwrite a file
//! that someone other than the attack changed after the copy, as far as
//! the guard saw it (write-opens kept in memory, 8 per inode; after a
//! restart only a newer mtime), and never guesses: when it cannot tell, it
//! writes the original beside the file (`<name>.nn-restored-<entry>`) and
//! reports both — the operator decides.
//!
//! 1. The journal's copy is missing or its SHA-256 does not match the
//!    index: **refused** (`journal_corrupt`).
//! 2. Nothing at the path (the attack renamed or deleted the file):
//!    **recreated** from the copy, with its mode and owner.
//! 3. Not a regular file at the path: **kept both**.
//! 4. Content equal to the original (whatever the inode — a file this
//!    guard recreated, an operator's own restore): **unchanged**.
//! 5. Not surely the same file at the path (another inode, or the inode
//!    number with another birth time — or none known to compare: lot 315,
//!    after the review of #542): **kept both**.
//! 6. Same file, a write-open of it after the copy by a process outside
//!    the attack's tree (a trusted editor, or anyone else), or by a process
//!    of the tree that still runs: **kept both**.
//! 7. Same inode, the copy predates this run of the guard (the agent
//!    restarted since: a write-open in between was not seen) and the file
//!    was modified after the copy: **kept both**.
//! 8. Otherwise (the attack's writes only): **restored in place** — same
//!    inode, links, extended attributes; content and modification time of
//!    the original.

use super::identity::FileId;
use super::index::{Entry, PostWrite};
use super::trust::ProcId;

/// The file at the entry's path now (`lstat`, never through a link).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Current {
    pub exists: bool,
    pub regular: bool,
    pub dev: u64,
    pub ino: u64,
    pub mtime_ns: i64,
    /// Birth time (ns), where the filesystem records it.
    pub btime_ns: Option<i64>,
}

impl Current {
    pub const MISSING: Current = Current {
        exists: false,
        regular: false,
        dev: 0,
        ino: 0,
        mtime_ns: 0,
        btime_ns: None,
    };

    /// The file's identity (see [`super::identity`]).
    pub const fn id(&self) -> FileId {
        FileId::new(self.dev, self.ino, self.btime_ns)
    }

    /// Surely the same file as the copy's: same device and inode, and
    /// both birth times known and equal (an inode number freed and given to
    /// a new file is another file). Lot 315, after the review of #542
    /// (F2): a birth time not known on either side is not "the same" —
    /// rule 5 then keeps both; with `may_be` here, a new file of the
    /// owner's that inherited the number at the same path (a filesystem
    /// without birth times, one open: `cp`, `tar -x`) was restored IN
    /// PLACE over.
    pub fn same_file(&self, f: &super::index::FileState) -> bool {
        self.id().surely_is(&f.id())
    }
}

/// What to do with one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    InPlace,
    Recreate,
    KeepBoth(String),
    Unchanged,
    Refuse(String),
}

impl Plan {
    pub fn action(&self) -> &'static str {
        match self {
            Plan::InPlace => "restored_in_place",
            Plan::Recreate => "recreated",
            Plan::KeepBoth(_) => "kept_both",
            Plan::Unchanged => "unchanged",
            Plan::Refuse(_) => "refused",
        }
    }
}

/// The inputs [`decide`] weighs besides the entry and the file now.
pub struct Context<'a> {
    /// The journal's copy is present and hashes to the entry's SHA-256.
    pub object_ok: bool,
    /// The current content's SHA-256 equals the original's (`None`: not
    /// computed — the file is missing or not a regular file).
    pub content_is_original: Option<bool>,
    /// Write-opens of the file seen after the copy.
    pub post_writes: &'a [PostWrite],
    /// Is this write-open the attack's (see [`Selector::in_attack_write`])?
    pub in_attack: &'a dyn Fn(&PostWrite) -> bool,
    /// Does this process still run (same pid and start)?
    pub alive: &'a dyn Fn(ProcId) -> bool,
    /// The copy was taken before this run of the guard started.
    pub predates_run: bool,
}

/// The rules of the module documentation, in order.
pub fn decide(entry: &Entry, cur: &Current, cx: &Context<'_>) -> Plan {
    if !cx.object_ok {
        return Plan::Refuse(
            "journal_corrupt: the copy is missing or does not hash to the index".into(),
        );
    }
    if !cur.exists {
        return Plan::Recreate;
    }
    if !cur.regular {
        return Plan::KeepBoth("the path is no longer a regular file".into());
    }
    if cx.content_is_original == Some(true) {
        return Plan::Unchanged;
    }
    if !cur.same_file(&entry.file) {
        if cur.id().may_be(&entry.file.id()) {
            return Plan::KeepBoth(
                "the file at the path has the copy's inode number, but no birth time tells it \
                 from a new file that inherited the number"
                    .into(),
            );
        }
        return Plan::KeepBoth("the file was replaced by another (a new file at the path)".into());
    }
    // Lot 315, after the review of #542 (F3): a write-open of the attack's
    // tree by a process that still runs (its own copy not taken: shared,
    // refused for room or time) blocks an in-place restore, as on main.
    if let Some(p) = cx
        .post_writes
        .iter()
        .find(|p| p.at_ms >= entry.taken_at_ms && (!(cx.in_attack)(p) || (cx.alive)(p.writer)))
    {
        if (cx.in_attack)(p) {
            return Plan::KeepBoth(format!(
                "changed after the copy by {} (pid {}) of the attack's tree, which still runs — \
                 contain it first",
                p.program, p.writer.pid
            ));
        }
        return Plan::KeepBoth(format!(
            "changed after the copy by {} writer {} (pid {})",
            if p.trusted { "trusted" } else { "another" },
            p.program,
            p.writer.pid
        ));
    }
    if cx.predates_run && cur.mtime_ns > entry.file.mtime_ns {
        return Plan::KeepBoth(
            "modified since the copy, partly while the guard was not running (agent restarted)"
                .into(),
        );
    }
    Plan::InPlace
}

/// Which entries a restore covers.
#[derive(Debug, Clone, Default)]
pub struct Selector {
    /// Processes whose trees are undone (empty: any).
    pub roots: Vec<ProcId>,
    /// Copies taken at or after this Unix time in milliseconds.
    pub since_ms: Option<u64>,
}

impl Selector {
    pub fn matches(&self, e: &Entry) -> bool {
        if self.since_ms.is_some_and(|s| e.taken_at_ms < s) {
            return false;
        }
        self.roots.is_empty() || self.roots.iter().any(|r| e.in_tree_of(*r))
    }

    /// Is `p` in one of the trees (as a writer or an ancestor named by a
    /// selected entry)? With no roots, every writer of a selected entry is.
    pub fn in_attack(&self, selected: &[&Entry], p: ProcId) -> bool {
        let named = |e: &&Entry| {
            e.writer.pid == p.pid
                && (p.start == 0 || e.writer.start == 0 || e.writer.start == p.start)
        };
        if self.roots.is_empty() {
            return selected.iter().any(named);
        }
        self.roots
            .iter()
            .any(|r| r.pid == p.pid && (r.start == 0 || p.start == 0 || r.start == p.start))
            || selected.iter().any(named)
    }

    /// Is the write-open `w` the attack's? Its writer is (see
    /// [`Self::in_attack`]); or, with roots, one of the roots was its
    /// writer's ancestor when it opened the file — lot 315 (BUG-93): a
    /// writer of the tree whose own copy was not taken (a copy shared,
    /// refused for room or time) is the tree's too. Without roots
    /// (`--since` alone) a lineage names no attack: a write-open is the
    /// attack's only when its writer has a selected copy, so a later edit
    /// by a program of the owner's that has its own copy is never taken
    /// for the attack's and overwritten.
    pub fn in_attack_write(&self, selected: &[&Entry], w: &PostWrite) -> bool {
        self.in_attack(selected, w.writer) || self.roots.iter().any(|r| w.in_tree_of(*r))
    }

    /// The copies a restore weighs a file's writers against: with roots,
    /// every copy the selector matches — lot 315 (BUG-93): two processes
    /// of the tree that each took a copy of a file are both the attack's,
    /// and a writer still running is one of them whichever copy was
    /// picked; without roots (`--since` alone), the picked copies only
    /// (a selected copy makes its writer the attack's, see
    /// [`Self::in_attack_write`]).
    pub fn weighed<'a>(
        &self,
        entries: impl Iterator<Item = &'a Entry>,
        picked: &[&'a Entry],
    ) -> Vec<&'a Entry> {
        if self.roots.is_empty() {
            return picked.to_vec();
        }
        entries.filter(|e| self.matches(e)).collect()
    }
}

/// The entries to restore: those `sel` matches, one per file — the
/// earliest, the content from before the attack's first write. Lot 315
/// (BUG-110): one per *file* — two files that had the same inode number
/// one after the other (birth times known and different) are two, and
/// neither is dropped. After the review of #542 (F5): an entry whose birth
/// time is not known joins the others of its inode number only when they
/// are at most one file (one known birth time, or none): beside two known
/// files it stands alone, never grouping them into one (`may_be` alone is
/// not transitive: such an entry, the earliest, swallowed both).
pub fn pick<'a>(entries: impl Iterator<Item = &'a Entry>, sel: &Selector) -> Vec<&'a Entry> {
    let mut slots: std::collections::BTreeMap<super::identity::Slot, Vec<&Entry>> =
        Default::default();
    for e in entries.filter(|e| sel.matches(e)) {
        slots.entry(e.file.id().slot()).or_default().push(e);
    }
    let mut v: Vec<&Entry> = Vec::new();
    for mut same_slot in slots.into_values() {
        same_slot.sort_by_key(|e| (e.taken_at_ms, e.id));
        let known: std::collections::BTreeSet<i64> =
            same_slot.iter().filter_map(|e| e.file.btime_ns).collect();
        let one_file = known.len() <= 1;
        let first = v.len();
        for e in same_slot {
            let unknown = |x: &Entry| x.file.btime_ns.is_none();
            let joins = v[first..]
                .iter()
                .any(|k| k.file.id() == e.file.id() || (one_file && (unknown(k) || unknown(e))));
            if !joins {
                v.push(e);
            }
        }
    }
    v.sort_by_key(|e| e.id);
    v
}

/// The name of the copy written beside a file kept both.
pub fn beside_name(file_name: &str, entry_id: u64) -> String {
    format!("{file_name}.nn-restored-{entry_id}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cow::index::{FileState, Method};

    fn entry(id: u64, ino: u64, writer: u32, at: u64) -> Entry {
        Entry {
            id,
            object: id,
            scope: 0,
            file: FileState {
                path: format!("/srv/t/f{ino}"),
                dev: 8,
                ino,
                size: 10,
                mtime_ns: 1_000,
                ctime_ns: 1_000,
                mode: 0o100644,
                uid: 1000,
                gid: 1000,
                btime_ns: Some(5),
            },
            sha256: "ab".into(),
            writer: ProcId {
                pid: writer,
                start: 50,
            },
            writer_program: "/home/u/sim.py".into(),
            lineage: vec![
                ProcId {
                    pid: writer,
                    start: 50,
                },
                ProcId { pid: 40, start: 10 },
            ],
            taken_at_ms: at,
            method: Method::Copy,
        }
    }

    fn same(e: &Entry, mtime: i64) -> Current {
        Current {
            exists: true,
            regular: true,
            dev: e.file.dev,
            ino: e.file.ino,
            mtime_ns: mtime,
            btime_ns: Some(5),
        }
    }

    fn cx<'a>(post: &'a [PostWrite], in_attack: &'a dyn Fn(&PostWrite) -> bool) -> Context<'a> {
        Context {
            object_ok: true,
            content_is_original: Some(false),
            post_writes: post,
            in_attack,
            alive: &|_| false,
            predates_run: false,
        }
    }

    fn attacker(p: &PostWrite) -> bool {
        p.writer.pid == 77
    }

    #[test]
    fn the_attacks_writes_only_are_restored_in_place() {
        let e = entry(1, 1, 77, 100);
        let post = [PostWrite {
            file: e.file.id(),
            at_ms: 150,
            writer: ProcId { pid: 77, start: 50 },
            program: "/home/u/sim.py".into(),
            trusted: false,
            lineage: vec![],
        }];
        assert_eq!(
            decide(&e, &same(&e, 9_999), &cx(&post, &attacker)),
            Plan::InPlace
        );
    }

    #[test]
    fn a_trusted_writer_after_the_attack_means_keep_both() {
        let e = entry(1, 1, 77, 100);
        let post = [PostWrite {
            file: e.file.id(),
            at_ms: 200,
            writer: ProcId { pid: 90, start: 60 },
            program: "/usr/bin/vim.basic".into(),
            trusted: true,
            lineage: vec![],
        }];
        match decide(&e, &same(&e, 9_999), &cx(&post, &attacker)) {
            Plan::KeepBoth(why) => {
                assert!(why.contains("trusted writer /usr/bin/vim.basic"), "{why}")
            }
            other => panic!("{other:?}"),
        }
        // a write-open before the copy is not "after"
        let early = [PostWrite {
            at_ms: 50,
            ..post[0].clone()
        }];
        assert_eq!(
            decide(&e, &same(&e, 9_999), &cx(&early, &attacker)),
            Plan::InPlace
        );
    }

    #[test]
    fn missing_replaced_unchanged_corrupt() {
        let e = entry(1, 1, 77, 100);
        let none: [PostWrite; 0] = [];
        assert_eq!(
            decide(&e, &Current::MISSING, &cx(&none, &attacker)),
            Plan::Recreate
        );
        let mut other = same(&e, 1);
        other.ino = 2;
        assert!(matches!(
            decide(&e, &other, &cx(&none, &attacker)),
            Plan::KeepBoth(_)
        ));
        let mut dir = same(&e, 1);
        dir.regular = false;
        assert!(matches!(
            decide(&e, &dir, &cx(&none, &attacker)),
            Plan::KeepBoth(_)
        ));
        let mut c = cx(&none, &attacker);
        c.content_is_original = Some(true);
        assert_eq!(decide(&e, &same(&e, 1), &c), Plan::Unchanged);
        let mut c = cx(&none, &attacker);
        c.object_ok = false;
        assert!(matches!(decide(&e, &Current::MISSING, &c), Plan::Refuse(_)));
    }

    #[test]
    fn a_reused_inode_number_is_another_file() {
        let e = entry(1, 1, 77, 100);
        let none: [PostWrite; 0] = [];
        let mut reborn = same(&e, 1);
        reborn.btime_ns = Some(6);
        assert!(matches!(
            decide(&e, &reborn, &cx(&none, &attacker)),
            Plan::KeepBoth(_)
        ));
        // Lot 315, after the review of #542 (F2): a birth time not known on
        // one side, or on both (a filesystem that records none), cannot
        // tell a new file that inherited the number — kept both, never an
        // overwrite (main restored it in place: "the inode decides")
        reborn.btime_ns = None;
        match decide(&e, &reborn, &cx(&none, &attacker)) {
            Plan::KeepBoth(why) => assert!(why.contains("no birth time"), "{why}"),
            other => panic!("{other:?}"),
        }
        let mut no_btime = e.clone();
        no_btime.file.btime_ns = None;
        assert!(matches!(
            decide(&no_btime, &reborn, &cx(&none, &attacker)),
            Plan::KeepBoth(_)
        ));
        // known and equal on both sides: the attack's writes only, in place
        assert_eq!(
            decide(&e, &same(&e, 1), &cx(&none, &attacker)),
            Plan::InPlace
        );
    }

    #[test]
    fn the_original_content_on_another_inode_is_unchanged() {
        let e = entry(1, 1, 77, 100);
        let none: [PostWrite; 0] = [];
        let mut recreated = same(&e, 1);
        recreated.ino = 99;
        let mut c = cx(&none, &attacker);
        c.content_is_original = Some(true);
        assert_eq!(decide(&e, &recreated, &c), Plan::Unchanged);
    }

    #[test]
    fn a_copy_from_an_earlier_run_is_not_overwritten_blind() {
        let e = entry(1, 1, 77, 100);
        let none: [PostWrite; 0] = [];
        let mut c = cx(&none, &attacker);
        c.predates_run = true;
        assert!(matches!(
            decide(&e, &same(&e, 2_000), &c),
            Plan::KeepBoth(_)
        ));
        // not modified since the copy: nothing to lose
        assert_eq!(decide(&e, &same(&e, 1_000), &c), Plan::InPlace);
        // and a missing file is recreated whatever the run
        assert_eq!(decide(&e, &Current::MISSING, &c), Plan::Recreate);
    }

    #[test]
    fn pick_takes_the_earliest_copy_of_each_file_in_the_tree() {
        let a = entry(1, 1, 77, 100);
        let b = entry(2, 1, 78, 50); // another writer of file 1, earlier
        let mut b_in_tree = entry(3, 1, 79, 120);
        b_in_tree.lineage.push(ProcId { pid: 77, start: 50 });
        let c = entry(4, 2, 77, 300);
        let d = entry(5, 3, 99, 400);
        let all = [a.clone(), b, b_in_tree, c.clone(), d];
        let sel = Selector {
            roots: vec![ProcId { pid: 77, start: 50 }],
            since_ms: None,
        };
        let picked = pick(all.iter(), &sel);
        assert_eq!(picked.iter().map(|e| e.id).collect::<Vec<_>>(), vec![1, 4]);
        let sel = Selector {
            roots: vec![],
            since_ms: Some(110),
        };
        let picked = pick(all.iter(), &sel);
        assert_eq!(
            picked.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![3, 4, 5]
        );
        // the attack: the roots and the selected writers
        let sel = Selector {
            roots: vec![ProcId { pid: 77, start: 0 }],
            since_ms: None,
        };
        let picked = pick(all.iter(), &sel);
        assert!(sel.in_attack(&picked, ProcId { pid: 77, start: 50 }));
        assert!(!sel.in_attack(&picked, ProcId { pid: 90, start: 1 }));
        assert_eq!(beside_name("a.txt", 4), "a.txt.nn-restored-4");
    }
}

/// Lot 315 (external bug hunt 1.4: BUG-110, BUG-93).
#[cfg(test)]
mod lot315 {
    use super::*;
    use crate::cow::index::{FileState, Method};

    fn entry(id: u64, path: &str, btime: Option<i64>, writer: u32, at: u64) -> Entry {
        let w = ProcId {
            pid: writer,
            start: 50,
        };
        Entry {
            id,
            object: id,
            scope: 0,
            file: FileState {
                path: path.into(),
                dev: 1,
                ino: 5,
                size: 10,
                mtime_ns: 1_000,
                ctime_ns: 1_000,
                mode: 0o100644,
                uid: 1000,
                gid: 1000,
                btime_ns: btime,
            },
            sha256: "ab".into(),
            writer: w,
            writer_program: "/home/u/enc.py".into(),
            lineage: vec![
                w,
                ProcId {
                    pid: 100,
                    start: 10,
                },
            ],
            taken_at_ms: at,
            method: Method::Copy,
        }
    }

    fn tree() -> Selector {
        Selector {
            roots: vec![ProcId {
                pid: 100,
                start: 10,
            }],
            since_ms: None,
        }
    }

    /// BUG-110: /srv/a (inode 5, born at 100) copied, then deleted; /srv/b
    /// gets inode number 5 (born at 200) and is copied too. Two files by the
    /// project's own rule (`Current::same_file`): one entry each (on main
    /// /srv/b was dropped without a row).
    #[test]
    fn bug110_pick_keeps_one_entry_per_file_not_per_inode_number() {
        let all = [
            entry(1, "/srv/a", Some(100), 101, 1000),
            entry(2, "/srv/b", Some(200), 102, 2000),
        ];
        let b_now = Current {
            exists: true,
            regular: true,
            dev: 1,
            ino: 5,
            mtime_ns: 1,
            btime_ns: Some(200),
        };
        assert!(!b_now.same_file(&all[0].file), "two files for the project");
        let paths: Vec<&str> = pick(all.iter(), &tree())
            .iter()
            .map(|e| e.file.path.as_str())
            .collect();
        assert_eq!(
            paths,
            ["/srv/a", "/srv/b"],
            "pick promises one entry per file: /srv/b is dropped without a row"
        );
        // and each file keeps its earliest copy, whatever the order read
        let mut more = all.to_vec();
        more.push(entry(3, "/srv/b", Some(200), 103, 1500));
        more.push(entry(4, "/srv/a", Some(100), 104, 500));
        let ids: Vec<u64> = pick(more.iter().rev(), &tree())
            .iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(ids, [3, 4]);
    }

    /// BUG-110 guard: one file, two writers (same birth time, or one not
    /// known): the earliest copy only.
    #[test]
    fn bug110_guard_one_file_two_writers_is_one_entry() {
        for (b1, b2) in [(Some(100), Some(100)), (None, Some(100)), (None, None)] {
            let all = [
                entry(1, "/srv/a", b1, 101, 1000),
                entry(2, "/srv/a", b2, 102, 2000),
            ];
            let ids: Vec<u64> = pick(all.iter(), &tree()).iter().map(|e| e.id).collect();
            assert_eq!(ids, [1], "{b1:?} {b2:?}");
        }
    }

    /// BUG-110 after the review of #542 (F5): an entry without a birth
    /// time, the earliest, does not group two files that are known to be
    /// two — each keeps its row (on the lot's first head only the unknown
    /// one was picked); next to one known file it is that file.
    #[test]
    fn bug110_an_entry_without_birth_time_never_groups_two_files() {
        let all = [
            entry(1, "/srv/u", None, 100, 500),
            entry(2, "/srv/a", Some(100), 101, 1000),
            entry(3, "/srv/b", Some(200), 102, 2000),
        ];
        let paths: Vec<&str> = pick(all.iter(), &tree())
            .iter()
            .map(|e| e.file.path.as_str())
            .collect();
        assert_eq!(paths, ["/srv/u", "/srv/a", "/srv/b"]);
        // later instead of earliest: the same
        let all = [
            entry(1, "/srv/a", Some(100), 101, 1000),
            entry(2, "/srv/b", Some(200), 102, 2000),
            entry(3, "/srv/u", None, 100, 3000),
        ];
        assert_eq!(pick(all.iter(), &tree()).len(), 3);
        // with one known file it is that file: the earliest of the two
        let all = [
            entry(1, "/srv/a", None, 100, 500),
            entry(2, "/srv/a", Some(100), 101, 1000),
            entry(3, "/srv/a", Some(100), 102, 2000),
        ];
        let ids: Vec<u64> = pick(all.iter(), &tree()).iter().map(|e| e.id).collect();
        assert_eq!(ids, [1]);
        // the unknown one later: it joins the one known file too
        let all = [
            entry(1, "/srv/a", Some(100), 101, 1000),
            entry(2, "/srv/a", None, 102, 2000),
        ];
        let ids: Vec<u64> = pick(all.iter(), &tree()).iter().map(|e| e.id).collect();
        assert_eq!(ids, [1]);
    }

    fn write_by(pid: u32, lineage: Vec<ProcId>) -> PostWrite {
        PostWrite {
            file: FileId::new(1, 5, Some(100)),
            at_ms: 3000,
            writer: ProcId { pid, start: 50 },
            program: "/home/u/enc.py".into(),
            trusted: false,
            lineage,
        }
    }

    /// BUG-93: with roots, every copy the selector matches is weighed (a
    /// second writer of the tree is the attack's whichever copy was
    /// picked), and a write-open whose writer descends from a root is the
    /// attack's; with `--since` alone, only the picked copies, and a
    /// lineage names no attack.
    #[test]
    fn bug93_the_tree_is_weighed_from_its_roots_only() {
        let all = [
            entry(1, "/srv/a", Some(100), 101, 1000),
            entry(2, "/srv/a", Some(100), 102, 2000),
        ];
        let sel = tree();
        let picked = pick(all.iter(), &sel);
        assert_eq!(picked.len(), 1);
        let weighed = sel.weighed(all.iter(), &picked);
        assert_eq!(weighed.iter().map(|e| e.id).collect::<Vec<_>>(), [1, 2]);
        assert!(sel.in_attack_write(&weighed, &write_by(102, vec![])));
        assert!(!sel.in_attack_write(&picked, &write_by(102, vec![])));
        // a writer with no copy of its own, of the tree by its lineage
        let root = ProcId {
            pid: 100,
            start: 10,
        };
        assert!(sel.in_attack_write(&picked, &write_by(103, vec![root])));
        assert!(sel.in_attack_write(&picked, &write_by(103, vec![ProcId { pid: 100, start: 0 }])));
        assert!(!sel.in_attack_write(
            &picked,
            &write_by(
                103,
                vec![ProcId {
                    pid: 100,
                    start: 11
                }]
            )
        ));
        assert!(!sel.in_attack_write(&picked, &write_by(103, vec![])));
        // --since alone: the picked copies, and no lineage
        let since = Selector {
            roots: vec![],
            since_ms: Some(0),
        };
        let picked = pick(all.iter(), &since);
        let weighed = since.weighed(all.iter(), &picked);
        assert_eq!(weighed.iter().map(|e| e.id).collect::<Vec<_>>(), [1]);
        assert!(!since.in_attack_write(&weighed, &write_by(102, vec![])));
        assert!(!since.in_attack_write(&weighed, &write_by(103, vec![root])));
        assert!(since.in_attack_write(&weighed, &write_by(101, vec![])));
    }
}
