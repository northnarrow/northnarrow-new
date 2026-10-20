//! The journal's content index: what was copied, for whom, and what it
//! costs — pure bookkeeping, no I/O (the journal and the guard do the
//! files).
//!
//! - An **object** is one copy of a file's content, counted against its
//!   scope's byte budget at the file's logical size (a reflink too: an
//!   attacker who rewrites the whole file unshares every block).
//! - An **entry** says which writer an object protects against: the file
//!   (path, device, inode, size, times, mode, owner), the writer (pid,
//!   start, program, lineage), when, how. Copy on *first* write: one entry
//!   per file and writer process; a second writer of a file unchanged
//!   since the last copy shares that copy (`Linked`) instead of taking
//!   another.
//! - **Retention**: an object older than the retention is dropped.
//! - **Budget**: a copy that does not fit evicts the least recently used
//!   objects of its scope, but never one younger than the eviction floor:
//!   during an attack the earliest copies are the ones that matter, and an
//!   attacker who churns files first must not push them out. When the
//!   room cannot be made, the copy is refused (`BudgetFull`, a signed
//!   degradation) — the file is not protected, the journal keeps what it
//!   has.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use super::trust::ProcId;

/// How an object was taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// `FICLONE`: shared extents, copy on write by the filesystem.
    Reflink,
    /// A bounded byte copy (`copy_file_range`, else read/write).
    Copy,
    /// No new object: the file was unchanged since an earlier copy.
    Linked,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Reflink => "reflink",
            Method::Copy => "copy",
            Method::Linked => "linked",
        }
    }
}

/// The file as it was when the copy was taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileState {
    pub path: String,
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Birth time (ns), where the filesystem records it.
    #[serde(default)]
    pub btime_ns: Option<i64>,
}

/// One journal entry (persisted as a line of `index.jsonl`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: u64,
    pub object: u64,
    pub scope: usize,
    pub file: FileState,
    /// SHA-256 of the object's content (hex).
    pub sha256: String,
    pub writer: ProcId,
    pub writer_program: String,
    /// The writer's lineage, writer first.
    pub lineage: Vec<ProcId>,
    /// Unix time in milliseconds.
    pub taken_at_ms: u64,
    pub method: Method,
}

impl Entry {
    /// The entry's writer, or one of its ancestors when it was taken, is
    /// `p` (a start of 0 matches any start of that pid).
    pub fn in_tree_of(&self, p: ProcId) -> bool {
        self.lineage
            .iter()
            .chain(std::iter::once(&self.writer))
            .any(|h| h.pid == p.pid && (p.start == 0 || h.start == 0 || h.start == p.start))
    }
}

/// One object's bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectInfo {
    pub scope: usize,
    pub bytes: u64,
    pub method: Method,
    pub taken_at_ms: u64,
    /// Last time an entry was added for it (LRU).
    pub used_at_ms: u64,
    pub refs: u32,
}

/// A write-open of a journaled file seen after its copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostWrite {
    pub at_ms: u64,
    pub writer: ProcId,
    pub program: String,
    pub trusted: bool,
}

/// Room held for a copy in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reservation {
    pub scope: usize,
    pub bytes: u64,
    pub object: u64,
}

/// Why a copy gets no room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Larger than the whole budget.
    LargerThanBudget,
    /// The budget is held by copies younger than the eviction floor.
    BudgetFull,
    UnknownScope,
}

/// A scope's budget and use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    pub budget: u64,
    pub used: u64,
    pub reserved: u64,
}

/// Bound on the post-write records kept per inode.
const POST_WRITES_PER_INODE: usize = 8;

/// The index.
#[derive(Debug, Clone, Default)]
pub struct JournalIndex {
    entries: BTreeMap<u64, Entry>,
    by_inode: HashMap<(u64, u64), Vec<u64>>,
    objects: HashMap<u64, ObjectInfo>,
    scopes: Vec<Usage>,
    post_writes: HashMap<(u64, u64), Vec<PostWrite>>,
    next_entry: u64,
    next_object: u64,
    retention_ms: u64,
    floor_ms: u64,
}

impl JournalIndex {
    /// An empty index for scopes with `budgets`, keeping objects for
    /// `retention_ms` and never evicting one younger than `floor_ms`.
    pub fn new(budgets: &[u64], retention_ms: u64, floor_ms: u64) -> Self {
        Self {
            scopes: budgets
                .iter()
                .map(|b| Usage {
                    budget: *b,
                    ..Usage::default()
                })
                .collect(),
            next_entry: 1,
            next_object: 1,
            retention_ms,
            floor_ms,
            ..Self::default()
        }
    }

    pub fn usage(&self, scope: usize) -> Option<Usage> {
        self.scopes.get(scope).copied()
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    pub fn entry(&self, id: u64) -> Option<&Entry> {
        self.entries.get(&id)
    }

    pub fn entry_count(&self, scope: usize) -> usize {
        self.entries.values().filter(|e| e.scope == scope).count()
    }

    pub fn object_count(&self, scope: usize) -> usize {
        self.objects.values().filter(|o| o.scope == scope).count()
    }

    pub fn object(&self, id: u64) -> Option<&ObjectInfo> {
        self.objects.get(&id)
    }

    /// The inode has an entry (a write-open of it is worth recording).
    pub fn has_inode(&self, dev: u64, ino: u64) -> bool {
        self.by_inode.contains_key(&(dev, ino))
    }

    /// Copy on first write: this writer has an entry for the inode.
    pub fn has_entry_for(&self, dev: u64, ino: u64, writer: ProcId) -> bool {
        self.by_inode.get(&(dev, ino)).is_some_and(|ids| {
            ids.iter()
                .filter_map(|id| self.entries.get(id))
                .any(|e| e.writer == writer)
        })
    }

    /// The latest object of the inode when the file is unchanged since it
    /// was taken (same size, mtime and ctime): a new writer shares it.
    pub fn reusable_object(&self, f: &FileState) -> Option<u64> {
        let ids = self.by_inode.get(&(f.dev, f.ino))?;
        let latest = ids
            .iter()
            .filter_map(|id| self.entries.get(id))
            .max_by_key(|e| (e.taken_at_ms, e.id))?;
        (latest.file.size == f.size
            && latest.file.mtime_ns == f.mtime_ns
            && latest.file.ctime_ns == f.ctime_ns
            && latest.file.btime_ns == f.btime_ns)
            .then_some(latest.object)
    }

    /// Hold room for a copy of `bytes` in `scope`. `Ok` with the
    /// reservation and the objects to evict first (their entries are gone
    /// from the index; the caller deletes the files).
    pub fn reserve(
        &mut self,
        scope: usize,
        bytes: u64,
        now_ms: u64,
    ) -> Result<(Reservation, Vec<u64>), Refusal> {
        let usage = *self.scopes.get(scope).ok_or(Refusal::UnknownScope)?;
        if bytes > usage.budget {
            return Err(Refusal::LargerThanBudget);
        }
        let need = (usage.used + usage.reserved + bytes).saturating_sub(usage.budget);
        let evicted = if need == 0 {
            Vec::new()
        } else {
            let plan = self.plan_eviction(scope, need, now_ms)?;
            for o in &plan {
                self.drop_object(*o);
            }
            plan
        };
        let object = self.next_object;
        self.next_object += 1;
        self.scopes[scope].reserved += bytes;
        Ok((
            Reservation {
                scope,
                bytes,
                object,
            },
            evicted,
        ))
    }

    /// The least recently used objects of `scope`, older than the floor,
    /// that free at least `need` bytes; `BudgetFull` when they do not.
    fn plan_eviction(&self, scope: usize, need: u64, now_ms: u64) -> Result<Vec<u64>, Refusal> {
        let cutoff = now_ms.saturating_sub(self.floor_ms);
        let mut candidates: Vec<(&u64, &ObjectInfo)> = self
            .objects
            .iter()
            .filter(|(_, o)| o.scope == scope && o.used_at_ms <= cutoff)
            .collect();
        candidates.sort_by_key(|(id, o)| (o.used_at_ms, **id));
        let mut freed = 0u64;
        let mut plan = Vec::new();
        for (id, o) in candidates {
            if freed >= need {
                break;
            }
            freed += o.bytes;
            plan.push(*id);
        }
        if freed >= need {
            Ok(plan)
        } else {
            Err(Refusal::BudgetFull)
        }
    }

    /// Give back a reservation whose copy was not taken.
    pub fn release(&mut self, r: Reservation) {
        if let Some(u) = self.scopes.get_mut(r.scope) {
            u.reserved = u.reserved.saturating_sub(r.bytes);
        }
    }

    /// The copy of a reservation was taken: record its object and entry.
    #[allow(clippy::too_many_arguments)]
    pub fn commit(
        &mut self,
        r: Reservation,
        file: FileState,
        sha256: String,
        writer: ProcId,
        writer_program: String,
        lineage: Vec<ProcId>,
        taken_at_ms: u64,
        method: Method,
    ) -> Entry {
        self.release(r);
        if let Some(u) = self.scopes.get_mut(r.scope) {
            u.used += r.bytes;
        }
        self.objects.insert(
            r.object,
            ObjectInfo {
                scope: r.scope,
                bytes: r.bytes,
                method,
                taken_at_ms,
                used_at_ms: taken_at_ms,
                refs: 0,
            },
        );
        self.add_entry(
            r.object,
            r.scope,
            file,
            sha256,
            writer,
            writer_program,
            lineage,
            taken_at_ms,
            method,
        )
    }

    /// A writer shares an existing object (see [`Self::reusable_object`]).
    #[allow(clippy::too_many_arguments)]
    pub fn link(
        &mut self,
        object: u64,
        file: FileState,
        writer: ProcId,
        writer_program: String,
        lineage: Vec<ProcId>,
        taken_at_ms: u64,
    ) -> Option<Entry> {
        let (scope, sha) = {
            let o = self.objects.get(&object)?;
            let sha = self
                .entries
                .values()
                .find(|e| e.object == object)
                .map(|e| e.sha256.clone())?;
            (o.scope, sha)
        };
        if let Some(o) = self.objects.get_mut(&object) {
            o.used_at_ms = o.used_at_ms.max(taken_at_ms);
        }
        Some(self.add_entry(
            object,
            scope,
            file,
            sha,
            writer,
            writer_program,
            lineage,
            taken_at_ms,
            Method::Linked,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn add_entry(
        &mut self,
        object: u64,
        scope: usize,
        file: FileState,
        sha256: String,
        writer: ProcId,
        writer_program: String,
        lineage: Vec<ProcId>,
        taken_at_ms: u64,
        method: Method,
    ) -> Entry {
        let id = self.next_entry;
        self.next_entry += 1;
        let e = Entry {
            id,
            object,
            scope,
            file,
            sha256,
            writer,
            writer_program,
            lineage,
            taken_at_ms,
            method,
        };
        self.insert_entry(e.clone());
        e
    }

    fn insert_entry(&mut self, e: Entry) {
        if let Some(o) = self.objects.get_mut(&e.object) {
            o.refs += 1;
        }
        self.by_inode
            .entry((e.file.dev, e.file.ino))
            .or_default()
            .push(e.id);
        self.next_entry = self.next_entry.max(e.id + 1);
        self.entries.insert(e.id, e);
    }

    /// Replay: an object read back from `index.jsonl`.
    pub fn restore_object(&mut self, id: u64, info: ObjectInfo) {
        if let Some(u) = self.scopes.get_mut(info.scope) {
            u.used += info.bytes;
        }
        self.next_object = self.next_object.max(id + 1);
        self.objects.insert(id, ObjectInfo { refs: 0, ..info });
    }

    /// Replay: an entry read back (its object restored first).
    pub fn restore_entry(&mut self, e: Entry) -> bool {
        if !self.objects.contains_key(&e.object) || e.scope >= self.scopes.len() {
            return false;
        }
        if let Some(o) = self.objects.get_mut(&e.object) {
            o.used_at_ms = o.used_at_ms.max(e.taken_at_ms);
        }
        self.insert_entry(e);
        true
    }

    /// Drop an object and every entry that references it.
    pub fn drop_object(&mut self, object: u64) -> Option<ObjectInfo> {
        let info = self.objects.remove(&object)?;
        if let Some(u) = self.scopes.get_mut(info.scope) {
            u.used = u.used.saturating_sub(info.bytes);
        }
        let ids: Vec<u64> = self
            .entries
            .values()
            .filter(|e| e.object == object)
            .map(|e| e.id)
            .collect();
        for id in ids {
            if let Some(e) = self.entries.remove(&id) {
                let key = (e.file.dev, e.file.ino);
                if let Some(v) = self.by_inode.get_mut(&key) {
                    v.retain(|x| *x != id);
                    if v.is_empty() {
                        self.by_inode.remove(&key);
                        self.post_writes.remove(&key);
                    }
                }
            }
        }
        Some(info)
    }

    /// Objects past the retention (dropped from the index; the caller
    /// deletes the files).
    pub fn expire(&mut self, now_ms: u64) -> Vec<u64> {
        let cutoff = now_ms.saturating_sub(self.retention_ms);
        let old: Vec<u64> = self
            .objects
            .iter()
            .filter(|(_, o)| o.used_at_ms < cutoff)
            .map(|(id, _)| *id)
            .collect();
        for id in &old {
            self.drop_object(*id);
        }
        old
    }

    /// A write-open of a journaled inode, after its copy.
    pub fn record_post_write(&mut self, dev: u64, ino: u64, w: PostWrite) {
        if !self.by_inode.contains_key(&(dev, ino)) {
            return;
        }
        let v = self.post_writes.entry((dev, ino)).or_default();
        if v.iter().any(|p| p.writer == w.writer) {
            return;
        }
        if v.len() >= POST_WRITES_PER_INODE {
            v.remove(0);
        }
        v.push(w);
    }

    /// The write-opens of the inode seen at or after `since_ms`.
    pub fn post_writes(&self, dev: u64, ino: u64, since_ms: u64) -> Vec<PostWrite> {
        self.post_writes
            .get(&(dev, ino))
            .map(|v| v.iter().filter(|p| p.at_ms >= since_ms).cloned().collect())
            .unwrap_or_default()
    }

    /// The object ids every entry references (the journal deletes the
    /// object files no entry names).
    pub fn live_objects(&self) -> impl Iterator<Item = &u64> {
        self.objects.keys()
    }

    /// The next object id (persisted ids never come back).
    pub fn next_object_id(&self) -> u64 {
        self.next_object
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: u64 = 60_000;

    fn file(ino: u64, size: u64) -> FileState {
        FileState {
            path: format!("/srv/t/f{ino}"),
            dev: 8,
            ino,
            size,
            mtime_ns: 1_000,
            ctime_ns: 1_000,
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            btime_ns: None,
        }
    }

    fn w(pid: u32) -> ProcId {
        ProcId { pid, start: 100 }
    }

    fn take(
        ix: &mut JournalIndex,
        ino: u64,
        size: u64,
        at: u64,
    ) -> Result<(Entry, Vec<u64>), Refusal> {
        let (r, evicted) = ix.reserve(0, size, at)?;
        let e = ix.commit(
            r,
            file(ino, size),
            "ab".into(),
            w(7),
            "/home/u/sim.py".into(),
            vec![w(7), w(1)],
            at,
            Method::Copy,
        );
        Ok((e, evicted))
    }

    #[test]
    fn the_budget_holds_and_lru_evicts_past_the_floor() {
        let mut ix = JournalIndex::new(&[100], 24 * 60 * MIN, 15 * MIN);
        let t0 = 1_000_000_000;
        take(&mut ix, 1, 40, t0).unwrap();
        take(&mut ix, 2, 40, t0 + MIN).unwrap();
        // 20 left; a 30-byte copy needs 10: nothing old enough yet
        assert_eq!(
            take(&mut ix, 3, 30, t0 + 2 * MIN).unwrap_err(),
            Refusal::BudgetFull
        );
        assert_eq!(ix.usage(0).unwrap().reserved, 0, "a refusal holds nothing");
        // past the floor, the least recently used object goes first
        let (_, evicted) = take(&mut ix, 3, 30, t0 + 20 * MIN).unwrap();
        assert_eq!(evicted.len(), 1);
        assert!(!ix.has_inode(8, 1), "the oldest object was evicted");
        assert!(ix.has_inode(8, 2));
        assert_eq!(ix.usage(0).unwrap().used, 70);
        assert_eq!(
            ix.reserve(0, 101, t0).unwrap_err(),
            Refusal::LargerThanBudget
        );
        assert_eq!(ix.reserve(9, 1, t0).unwrap_err(), Refusal::UnknownScope);
    }

    #[test]
    fn a_shared_object_is_used_again_and_survives_lru() {
        let mut ix = JournalIndex::new(&[100], 24 * 60 * MIN, 15 * MIN);
        let t0 = 1_000_000_000;
        let (a, _) = take(&mut ix, 1, 40, t0).unwrap();
        take(&mut ix, 2, 40, t0 + MIN).unwrap();
        // another writer of the unchanged file 1 shares its object
        assert_eq!(ix.reusable_object(&file(1, 40)), Some(a.object));
        let mut changed = file(1, 40);
        changed.mtime_ns += 1;
        assert_eq!(ix.reusable_object(&changed), None);
        let linked = ix
            .link(
                a.object,
                file(1, 40),
                w(9),
                "x".into(),
                vec![w(9)],
                t0 + 18 * MIN,
            )
            .unwrap();
        assert_eq!(linked.method, Method::Linked);
        assert_eq!(linked.sha256, "ab");
        assert_eq!(ix.object(a.object).unwrap().refs, 2);
        assert_eq!(ix.usage(0).unwrap().used, 80, "a link costs nothing");
        // object 2 is now the least recently used
        let (_, evicted) = take(&mut ix, 3, 30, t0 + 20 * MIN).unwrap();
        assert_eq!(ix.entry_count(0), 3);
        assert!(ix.has_inode(8, 1) && !ix.has_inode(8, 2), "{evicted:?}");
    }

    #[test]
    fn copy_on_first_write_is_per_writer() {
        let mut ix = JournalIndex::new(&[1000], 24 * 60 * MIN, 0);
        take(&mut ix, 1, 10, 1).unwrap();
        assert!(ix.has_entry_for(8, 1, w(7)));
        assert!(!ix.has_entry_for(8, 1, w(8)));
        assert!(!ix.has_entry_for(8, 1, ProcId { pid: 7, start: 101 }));
    }

    #[test]
    fn retention_drops_old_objects_and_their_entries() {
        let mut ix = JournalIndex::new(&[1000], 60 * MIN, 0);
        take(&mut ix, 1, 10, 0).unwrap();
        take(&mut ix, 2, 10, 50 * MIN).unwrap();
        let gone = ix.expire(70 * MIN);
        assert_eq!(gone.len(), 1);
        assert!(!ix.has_inode(8, 1) && ix.has_inode(8, 2));
        assert_eq!(ix.usage(0).unwrap().used, 10);
    }

    #[test]
    fn post_writes_are_kept_per_inode_and_bounded() {
        let mut ix = JournalIndex::new(&[1000], 60 * MIN, 0);
        take(&mut ix, 1, 10, 5).unwrap();
        ix.record_post_write(
            8,
            99,
            PostWrite {
                at_ms: 6,
                writer: w(1),
                program: "vim".into(),
                trusted: true,
            },
        );
        assert!(ix.post_writes(8, 99, 0).is_empty(), "not journaled");
        for pid in 0..20 {
            ix.record_post_write(
                8,
                1,
                PostWrite {
                    at_ms: 10 + pid as u64,
                    writer: w(pid),
                    program: "vim".into(),
                    trusted: true,
                },
            );
        }
        assert_eq!(ix.post_writes(8, 1, 0).len(), POST_WRITES_PER_INODE);
        assert_eq!(ix.post_writes(8, 1, 28).len(), 2);
    }

    #[test]
    fn replay_rebuilds_usage_and_ids() {
        let mut ix = JournalIndex::new(&[1000], 60 * MIN, 0);
        let (e, _) = take(&mut ix, 1, 10, 5).unwrap();
        let mut back = JournalIndex::new(&[1000], 60 * MIN, 0);
        back.restore_object(
            e.object,
            ObjectInfo {
                scope: 0,
                bytes: 10,
                method: Method::Copy,
                taken_at_ms: 5,
                used_at_ms: 5,
                refs: 0,
            },
        );
        assert!(back.restore_entry(e.clone()));
        let mut orphan = e.clone();
        orphan.object = 77;
        assert!(!back.restore_entry(orphan));
        assert_eq!(back.usage(0).unwrap().used, 10);
        assert!(back.next_object_id() > e.object);
        let (r, _) = back.reserve(0, 1, 6).unwrap();
        assert!(r.object > e.object);
    }

    #[test]
    fn tree_membership() {
        let mut ix = JournalIndex::new(&[1000], 60 * MIN, 0);
        let (e, _) = take(&mut ix, 1, 10, 5).unwrap();
        assert!(e.in_tree_of(ProcId { pid: 7, start: 100 }));
        assert!(e.in_tree_of(ProcId { pid: 7, start: 0 }));
        assert!(e.in_tree_of(ProcId { pid: 1, start: 100 }));
        assert!(!e.in_tree_of(ProcId { pid: 7, start: 5 }));
        assert!(!e.in_tree_of(ProcId { pid: 8, start: 100 }));
    }
}
