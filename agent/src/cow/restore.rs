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
//! 5. Another inode at the path (the file was replaced): **kept both**.
//! 6. Same inode, a write-open of it after the copy by a process outside
//!    the attack's tree (a trusted editor, or anyone else): **kept both**.
//! 7. Same inode, the copy predates this run of the guard (the agent
//!    restarted since: a write-open in between was not seen) and the file
//!    was modified after the copy: **kept both**.
//! 8. Otherwise (the attack's writes only): **restored in place** — same
//!    inode, links, extended attributes; content and modification time of
//!    the original.

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

    /// The same file as the copy's: same device and inode, and — where
    /// both are known — the same birth time (an inode number freed and
    /// given to a new file is another file).
    pub fn same_file(&self, f: &super::index::FileState) -> bool {
        (self.dev, self.ino) == (f.dev, f.ino)
            && match (self.btime_ns, f.btime_ns) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
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
    /// Write-opens of the inode seen after the copy.
    pub post_writes: &'a [PostWrite],
    /// Is this process part of the attack being undone?
    pub in_attack: &'a dyn Fn(ProcId) -> bool,
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
        return Plan::KeepBoth("the file was replaced by another (a new file at the path)".into());
    }
    if let Some(p) = cx
        .post_writes
        .iter()
        .find(|p| p.at_ms >= entry.taken_at_ms && !(cx.in_attack)(p.writer))
    {
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
}

/// The entries to restore: those `sel` matches, one per file — the
/// earliest, the content from before the attack's first write.
pub fn pick<'a>(entries: impl Iterator<Item = &'a Entry>, sel: &Selector) -> Vec<&'a Entry> {
    let mut by_inode: std::collections::BTreeMap<(u64, u64), &Entry> = Default::default();
    for e in entries.filter(|e| sel.matches(e)) {
        let key = (e.file.dev, e.file.ino);
        match by_inode.get(&key) {
            Some(prev) if (prev.taken_at_ms, prev.id) <= (e.taken_at_ms, e.id) => {}
            _ => {
                by_inode.insert(key, e);
            }
        }
    }
    let mut v: Vec<&Entry> = by_inode.into_values().collect();
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

    fn cx<'a>(post: &'a [PostWrite], in_attack: &'a dyn Fn(ProcId) -> bool) -> Context<'a> {
        Context {
            object_ok: true,
            content_is_original: Some(false),
            post_writes: post,
            in_attack,
            predates_run: false,
        }
    }

    fn attacker(p: ProcId) -> bool {
        p.pid == 77
    }

    #[test]
    fn the_attacks_writes_only_are_restored_in_place() {
        let e = entry(1, 1, 77, 100);
        let post = [PostWrite {
            at_ms: 150,
            writer: ProcId { pid: 77, start: 50 },
            program: "/home/u/sim.py".into(),
            trusted: false,
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
            at_ms: 200,
            writer: ProcId { pid: 90, start: 60 },
            program: "/usr/bin/vim.basic".into(),
            trusted: true,
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
        // a filesystem without birth times: the inode decides
        reborn.btime_ns = None;
        assert_eq!(decide(&e, &reborn, &cx(&none, &attacker)), Plan::InPlace);
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
