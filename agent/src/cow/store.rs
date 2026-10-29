//! The journals, their index, the counters and the restore — everything of
//! the guard but the fanotify loop ([`super::guard`]), so the restore runs
//! (and is tested) without the permission events.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use parking_lot::Mutex;
use tracing::{info, warn};

use super::config::CowConfig;
use super::copy::sha256_fd;
use super::index::{Entry, FileState, JournalIndex, Method, PostWrite, Refusal, Reservation};
use super::journal::{host_view, Journal, Record};
use super::restore::{beside_name, decide, pick, Context, Current, Plan, Selector};
use super::trust::{proc_start_ticks, ProcId};
use crate::audit::{AuditEntryDraft, AuditLog};

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

macro_rules! counters {
    ($($name:ident),* $(,)?) => {
        /// The guard's counters since the start (`status --key`).
        #[derive(Default)]
        pub struct Stats { $(pub $name: AtomicU64,)* }
        impl Stats {
            pub fn snapshot(&self) -> Vec<(String, u64)> {
                vec![$((stringify!($name).to_string(), self.$name.load(Ordering::Relaxed)),)*]
            }
        }
    };
}

counters!(
    events,
    allowed_own,
    allowed_not_regular,
    allowed_empty,
    allowed_read_only,
    allowed_trusted,
    allowed_outside_scope,
    allowed_already_copied,
    copies_reflink,
    copies_plain,
    copies_linked,
    copied_bytes,
    skipped_over_cap,
    skipped_deadline,
    skipped_budget_full,
    skipped_larger_than_budget,
    skipped_queue_full,
    skipped_low_space,
    skipped_source_changed,
    skipped_failed,
    skipped_unresolved_path,
    late_answered_by_backstop,
    queue_overflows,
    post_writes,
    answer_fast_count,
    answer_fast_us_total,
    answer_fast_us_max,
    answer_copy_count,
    answer_copy_us_total,
    answer_copy_us_max,
    restores,
    restored_files,
    restore_conflicts,
    restore_refused,
    evicted_objects,
    expired_objects,
);

impl Stats {
    pub fn bump(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an answer's latency (from the read of the event).
    pub fn answered(&self, copy: bool, us: u64) {
        let (n, total, max) = if copy {
            (
                &self.answer_copy_count,
                &self.answer_copy_us_total,
                &self.answer_copy_us_max,
            )
        } else {
            (
                &self.answer_fast_count,
                &self.answer_fast_us_total,
                &self.answer_fast_us_max,
            )
        };
        n.fetch_add(1, Ordering::Relaxed);
        total.fetch_add(us, Ordering::Relaxed);
        max.fetch_max(us, Ordering::Relaxed);
    }
}

/// Who asked for a restore.
#[derive(Debug, Clone)]
pub enum RestoreBy {
    /// A signed `remediate ransomware` (the primary signer's fingerprint).
    Admin { key_fp: String },
    /// COMBAT neutralized ransomware with `auto_restore = true`.
    Auto { source: String },
}

impl RestoreBy {
    fn key_fp(&self) -> String {
        match self {
            RestoreBy::Admin { key_fp } => key_fp.clone(),
            RestoreBy::Auto { .. } => "agent-self".into(),
        }
    }

    fn label(&self) -> String {
        match self {
            RestoreBy::Admin { .. } => "admin".into(),
            RestoreBy::Auto { source } => format!("auto ({source})"),
        }
    }
}

/// One file of a restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreRow {
    pub path: String,
    pub action: String,
    pub entry: u64,
    pub detail: String,
    pub beside: Option<String>,
    pub evidence: Option<String>,
    pub sha256_original: String,
    pub sha256_after: Option<String>,
}

/// A restore's outcome.
#[derive(Debug, Clone, Default)]
pub struct RestoreReport {
    pub rows: Vec<RestoreRow>,
    pub restored: u32,
    pub recreated: u32,
    pub kept_both: u32,
    pub unchanged: u32,
    pub refused: u32,
    pub skipped: u32,
    /// Why nothing was attempted (an ambiguous pid, no entry).
    pub refusal: Option<String>,
}

/// The guard's journals and index.
pub struct Store {
    pub cfg: CowConfig,
    pub index: Mutex<JournalIndex>,
    /// One per scope; `None` when the scope's journal could not be opened.
    pub journals: Vec<Option<Mutex<Journal>>>,
    /// The objects directory of each journal (`-1`: none). The descriptors
    /// live as long as the journals.
    pub objects_fds: Vec<RawFd>,
    pub stats: Stats,
    /// When this run of the guard started (Unix ms): a copy older than
    /// this was taken by an earlier run.
    pub run_started_ms: u64,
    audit: Mutex<Option<Arc<Mutex<AuditLog>>>>,
    /// The bpffs pin root the agent's anti-tamper maps live under (`None`:
    /// the anti-tamper layer did not come up), where a compacted index is
    /// registered again (R11c, lab PR 264: given at the open; it was a
    /// process-wide `protect::PIN_ROOT`).
    pin_root: Option<std::path::PathBuf>,
}

impl Store {
    /// Open every scope's journal and read its index back. A scope whose
    /// journal cannot be opened is reported and left unprotected.
    pub fn open(cfg: CowConfig, pin_root: Option<std::path::PathBuf>) -> (Arc<Self>, Vec<String>) {
        let budgets: Vec<u64> = cfg.scopes.iter().map(|s| s.budget).collect();
        let mut ix = JournalIndex::new(
            &budgets,
            cfg.retention_hours * 3_600_000,
            cfg.eviction_floor_minutes * 60_000,
        );
        let mut journals = Vec::new();
        let mut fds = Vec::new();
        let mut problems = Vec::new();
        for (i, s) in cfg.scopes.iter().enumerate() {
            match Journal::open(&s.journal) {
                Ok(j) => {
                    match j.replay(&mut ix, i) {
                        Ok(0) => {}
                        Ok(bad) => problems.push(format!(
                            "{}: {bad} unreadable line(s) of index.jsonl skipped",
                            s.journal.display()
                        )),
                        Err(e) => problems.push(format!("{}: {e:#}", s.journal.display())),
                    }
                    fds.push(j.objects_fd());
                    journals.push(Some(Mutex::new(j)));
                }
                Err(e) => {
                    problems.push(format!("{}: {e:#}", s.journal.display()));
                    fds.push(-1);
                    journals.push(None);
                }
            }
        }
        let store = Arc::new(Self {
            cfg,
            index: Mutex::new(ix),
            journals,
            objects_fds: fds,
            stats: Stats::default(),
            run_started_ms: now_ms(),
            audit: Mutex::new(None),
            pin_root,
        });
        store.remove_orphans();
        store.expire(now_ms());
        store.compact_all();
        (store, problems)
    }

    pub fn set_audit_log(&self, log: Option<Arc<Mutex<AuditLog>>>) {
        *self.audit.lock() = log;
    }

    /// Sign one row of the agent's audit chain.
    pub fn sign(&self, op: &str, extra: serde_json::Value, key_fp: &str, result: &str) {
        let Some(log) = self.audit.lock().clone() else {
            return;
        };
        let draft = AuditEntryDraft {
            op: op.to_string(),
            extra,
            key_fp: key_fp.to_string(),
            cosigner_fps: Vec::new(),
            result: result.to_string(),
            client_pid: std::process::id(),
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
            client_exe: None,
        };
        let appended = log.lock().append(draft);
        if let Err(e) = appended {
            warn!(error = %e, op, "copy on first write: signing an audit row failed");
        }
    }

    /// A signed degradation of the guard (`subsystem_degraded`).
    pub fn sign_degraded(&self, reason: &str, detail: &str, extra: serde_json::Value) {
        let mut v = serde_json::json!({
            "kind": "subsystem_degraded",
            "subsystem": "cow_guard",
            "reason": reason,
            "detail": detail,
            "at_boot": false,
        });
        if let (Some(obj), serde_json::Value::Object(more)) = (v.as_object_mut(), extra) {
            obj.extend(more);
        }
        self.sign(crate::self_integrity::AUDIT_OP, v, "agent-self", "detected");
    }

    fn journal(&self, scope: usize) -> Option<&Mutex<Journal>> {
        self.journals.get(scope).and_then(|j| j.as_ref())
    }

    /// Delete object files no index entry names (a copy taken while the
    /// agent stopped before recording it).
    fn remove_orphans(&self) {
        let live: std::collections::BTreeSet<u64> =
            self.index.lock().live_objects().copied().collect();
        for j in self.journals.iter().flatten() {
            let j = j.lock();
            for id in j.list_objects() {
                if !live.contains(&id) {
                    j.remove_object(id);
                }
            }
        }
    }

    /// Retention: drop objects past it and evidence files.
    pub fn expire(&self, now: u64) {
        let gone = self.index.lock().expire(now);
        if !gone.is_empty() {
            self.stats
                .expired_objects
                .fetch_add(gone.len() as u64, Ordering::Relaxed);
            info!(
                objects = gone.len(),
                "copy on first write: copies past the retention dropped"
            );
        }
        self.forget_objects(&gone);
        let cutoff = (now / 1000) as i64 - (self.cfg.retention_hours * 3600) as i64;
        for j in self.journals.iter().flatten() {
            j.lock().expire_evidence(cutoff);
        }
    }

    /// Delete dropped objects' files and record the drops.
    pub fn forget_objects(&self, objects: &[u64]) {
        if objects.is_empty() {
            return;
        }
        for j in self.journals.iter().flatten() {
            let mut j = j.lock();
            let present = j.list_objects();
            let mine: Vec<u64> = objects
                .iter()
                .copied()
                .filter(|o| present.contains(o))
                .collect();
            for o in &mine {
                j.remove_object(*o);
            }
            let recs: Vec<Record> = mine.iter().map(|o| Record::Drop { object: *o }).collect();
            if let Err(e) = j.append(&recs) {
                warn!(error = %e, "copy on first write: recording dropped copies failed");
            }
        }
    }

    /// The live records of `scope`: its copies and their entries.
    fn live_records(ix: &JournalIndex, scope: usize) -> Vec<Record> {
        let mut recs = Vec::new();
        let mut objects: std::collections::BTreeSet<u64> = Default::default();
        for e in ix.entries().filter(|e| e.scope == scope) {
            if objects.insert(e.object) {
                if let Some(o) = ix.object(e.object) {
                    recs.push(Record::Object {
                        id: e.object,
                        bytes: o.bytes,
                        method: o.method,
                        taken_at_ms: o.taken_at_ms,
                    });
                }
            }
            recs.push(Record::Entry {
                entry: Box::new(e.clone()),
            });
        }
        recs
    }

    /// Rewrite each index file with its live records when it has grown
    /// past four times them. The new file is created with no lock held
    /// (review of lab PR 222: on a scope marked by mount or filesystem that
    /// open is a permission event the guard's reader answers, and the
    /// reader takes these locks), then written under them.
    pub fn compact_all(&self) {
        for (scope, j) in self.journals.iter().enumerate() {
            let Some(j) = j else { continue };
            let host = {
                let ix = self.index.lock();
                let j = j.lock();
                let live = Self::live_records(&ix, scope).len() as u64;
                if j.lines() <= 4 * live + 1000 && (live > 0 || j.lines() == 0) {
                    continue;
                }
                j.host().to_path_buf()
            };
            let f = match Journal::compaction_file(&host) {
                Ok(f) => f,
                Err(e) => {
                    warn!(error = %e, "copy on first write: compacting index.jsonl failed");
                    continue;
                }
            };
            let ix = self.index.lock();
            let mut j = j.lock();
            let recs = Self::live_records(&ix, scope);
            let old = super::protect::index_key(&j);
            if let Err(e) = j.compact_into(f, &recs) {
                warn!(error = %e, "copy on first write: compacting index.jsonl failed");
            } else {
                super::protect::reprotect_index(&j, old, self.pin_root.as_deref());
            }
        }
    }

    /// Hold room for a copy, evicting old copies when needed: their ids
    /// come back for [`Self::forget_objects`] (the guard's index worker
    /// deletes the files, never the fanotify reader).
    pub fn reserve(
        &self,
        scope: usize,
        bytes: u64,
    ) -> std::result::Result<(Reservation, Vec<u64>), Refusal> {
        let (r, evicted) = self.index.lock().reserve(scope, bytes, now_ms())?;
        if !evicted.is_empty() {
            self.stats
                .evicted_objects
                .fetch_add(evicted.len() as u64, Ordering::Relaxed);
        }
        Ok((r, evicted))
    }

    pub fn release(&self, r: Reservation) {
        self.index.lock().release(r);
    }

    /// Record a taken copy: hash the object, commit the entry, persist.
    #[allow(clippy::too_many_arguments)]
    pub fn commit(
        &self,
        r: Reservation,
        file: FileState,
        writer: ProcId,
        program: String,
        lineage: Vec<ProcId>,
        taken_at_ms: u64,
        method: Method,
    ) -> Result<Entry> {
        let Some(j) = self.journal(r.scope) else {
            self.release(r);
            anyhow::bail!("scope {} has no journal", r.scope);
        };
        // The copy is opened and hashed with no lock held (review of lab PR
        // 222: on a scope marked by mount or filesystem the open is a
        // permission event the guard's reader answers, and the reader takes
        // the journal's lock; a long hash under it stalled the reader too).
        let objects = j.lock().objects_dir();
        let sha = match objects
            .and_then(|d| Journal::open_object_in(&d, r.object))
            .and_then(|fd| sha256_fd(fd.as_raw_fd()))
        {
            Ok(s) => s,
            Err(e) => {
                j.lock().remove_object(r.object);
                self.release(r);
                return Err(e.into());
            }
        };
        let entry =
            self.index
                .lock()
                .commit(r, file, sha, writer, program, lineage, taken_at_ms, method);
        j.lock().append(&[
            Record::Object {
                id: r.object,
                bytes: r.bytes,
                method,
                taken_at_ms,
            },
            Record::Entry {
                entry: Box::new(entry.clone()),
            },
        ])?;
        Ok(entry)
    }

    /// A second writer of an unchanged file shares its last copy.
    pub fn link(
        &self,
        object: u64,
        file: FileState,
        writer: ProcId,
        program: String,
        lineage: Vec<ProcId>,
    ) -> Option<Entry> {
        let e = self
            .index
            .lock()
            .link(object, file, writer, program, lineage, now_ms())?;
        if let Some(j) = self.journal(e.scope) {
            if let Err(err) = j.lock().append(&[Record::Entry {
                entry: Box::new(e.clone()),
            }]) {
                warn!(error = %err, "copy on first write: recording a shared copy failed");
            }
        }
        Some(e)
    }

    pub fn record_post_write(&self, dev: u64, ino: u64, w: PostWrite) {
        let mut ix = self.index.lock();
        if ix.has_inode(dev, ino) {
            ix.record_post_write(dev, ino, w);
            Stats::bump(&self.stats.post_writes);
        }
    }

    pub fn sync(&self) {
        for j in self.journals.iter().flatten() {
            j.lock().sync();
        }
    }

    /// Restore what `sel` covers (see [`super::restore`]). Every file
    /// attempted is a signed `cow_restore` row unless `dry_run`.
    pub fn restore(&self, sel: &Selector, dry_run: bool, by: &RestoreBy) -> RestoreReport {
        Stats::bump(&self.stats.restores);
        let mut report = RestoreReport::default();
        let entries: Vec<Entry> = {
            let ix = self.index.lock();
            if let Some(why) = ambiguous(ix.entries(), sel) {
                report.refusal = Some(why);
                return report;
            }
            pick(ix.entries(), sel).into_iter().cloned().collect()
        };
        if entries.is_empty() {
            report.refusal = Some("no copy in the journal matches".into());
            return report;
        }
        let refs: Vec<&Entry> = entries.iter().collect();
        for e in &entries {
            let row = self.restore_one(e, sel, &refs, dry_run);
            match row.action.trim_start_matches("would_") {
                "restored_in_place" => report.restored += 1,
                "recreated" => report.recreated += 1,
                "kept_both" => report.kept_both += 1,
                "unchanged" => report.unchanged += 1,
                "skipped" => report.skipped += 1,
                _ => report.refused += 1,
            }
            if !dry_run {
                match row.action.as_str() {
                    "restored_in_place" | "recreated" => Stats::bump(&self.stats.restored_files),
                    "kept_both" => Stats::bump(&self.stats.restore_conflicts),
                    "refused" => Stats::bump(&self.stats.restore_refused),
                    _ => {}
                }
                self.sign(
                    "cow_restore",
                    serde_json::json!({
                        "path": row.path,
                        "action": row.action,
                        "entry": row.entry,
                        "detail": row.detail,
                        "beside": row.beside,
                        "evidence": row.evidence,
                        "sha256_original": row.sha256_original,
                        "sha256_after": row.sha256_after,
                        "writer_pid": e.writer.pid,
                        "writer": e.writer_program,
                        "copied_at_ms": e.taken_at_ms,
                        "by": by.label(),
                    }),
                    &by.key_fp(),
                    &row.action,
                );
            }
            report.rows.push(row);
        }
        report
    }

    fn restore_one(
        &self,
        e: &Entry,
        sel: &Selector,
        selected: &[&Entry],
        dry_run: bool,
    ) -> RestoreRow {
        let mut row = RestoreRow {
            path: e.file.path.clone(),
            action: String::new(),
            entry: e.id,
            detail: String::new(),
            beside: None,
            evidence: None,
            sha256_original: e.sha256.clone(),
            sha256_after: None,
        };
        let finish = |mut row: RestoreRow, action: &str, detail: String| {
            row.action = if dry_run && action != "refused" && action != "skipped" {
                format!("would_{action}")
            } else {
                action.to_string()
            };
            row.detail = detail;
            row
        };
        if let Some(w) = selected
            .iter()
            .filter(|x| (x.file.dev, x.file.ino) == (e.file.dev, e.file.ino))
            .map(|x| x.writer)
            .find(|w| alive(*w))
        {
            return finish(
                row,
                "skipped",
                format!(
                    "its writer (pid {}) is still running — contain it first",
                    w.pid
                ),
            );
        }
        let Some(scope) = self.cfg.scopes.get(e.scope) else {
            return finish(row, "refused", "the scope is no longer configured".into());
        };
        let Ok(rel) = Path::new(&e.file.path).strip_prefix(&scope.path) else {
            return finish(row, "refused", "the path is outside its scope".into());
        };
        let (Some(name), parent) = (
            rel.file_name().and_then(|n| n.to_str()).map(str::to_string),
            rel.parent().unwrap_or(Path::new("")),
        ) else {
            return finish(row, "refused", "the path has no file name".into());
        };
        let root = match open_dir(&host_view(&scope.path)) {
            Ok(fd) => fd,
            Err(err) => return finish(row, "refused", format!("scope root: {err}")),
        };
        let dir = match open_beneath(root.as_raw_fd(), parent) {
            Ok(fd) => fd,
            Err(err) => {
                return finish(
                    row,
                    "refused",
                    format!("its directory cannot be reached without a link ({err})"),
                )
            }
        };
        let Some(jm) = self.journal(e.scope) else {
            return finish(row, "refused", "the scope has no journal".into());
        };
        // Opened with no lock held (see `commit`).
        let objects = jm.lock().objects_dir();
        let object = objects.and_then(|d| Journal::open_object_in(&d, e.object));
        let object_ok = object
            .as_ref()
            .ok()
            .and_then(|fd| sha256_fd(fd.as_raw_fd()).ok())
            .is_some_and(|h| h == e.sha256);
        let cur = match fstatat_nofollow(dir.as_raw_fd(), &name) {
            Ok(st) => Current {
                exists: true,
                regular: st.st_mode & libc::S_IFMT == libc::S_IFREG,
                dev: st.st_dev,
                ino: st.st_ino,
                mtime_ns: st.st_mtime * 1_000_000_000 + st.st_mtime_nsec,
                btime_ns: super::fanotify::btime(dir.as_raw_fd(), Some(&name)),
            },
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => Current::MISSING,
            Err(err) => return finish(row, "refused", format!("stat: {err}")),
        };
        let content_is_original = (cur.exists && cur.regular)
            .then(|| {
                open_at(dir.as_raw_fd(), &name, libc::O_RDONLY, 0)
                    .and_then(|fd| sha256_fd(fd.as_raw_fd()))
                    .ok()
                    .map(|h| h == e.sha256)
            })
            .flatten();
        let post = self
            .index
            .lock()
            .post_writes(e.file.dev, e.file.ino, e.taken_at_ms);
        let in_attack = |p: ProcId| sel.in_attack(selected, p);
        let plan = decide(
            e,
            &cur,
            &Context {
                object_ok,
                content_is_original,
                post_writes: &post,
                in_attack: &in_attack,
                predates_run: e.taken_at_ms < self.run_started_ms,
            },
        );
        let detail = match &plan {
            Plan::KeepBoth(why) | Plan::Refuse(why) => why.clone(),
            Plan::InPlace => "rewritten by the attack only".into(),
            Plan::Recreate => "missing (renamed or deleted by the attack)".into(),
            Plan::Unchanged => "content already the original".into(),
        };
        if dry_run || matches!(plan, Plan::Unchanged | Plan::Refuse(_)) {
            return finish(row, plan.action(), detail);
        }
        let Ok(object) = object else {
            return finish(row, "refused", "the copy cannot be opened".into());
        };
        let written = match &plan {
            Plan::InPlace => write_in_place(dir.as_raw_fd(), &name, &cur, object.as_raw_fd(), e),
            Plan::Recreate => write_new(dir.as_raw_fd(), &name, object.as_raw_fd(), e),
            Plan::KeepBoth(_) => {
                let b = beside_name(&name, e.id);
                let r = write_new(dir.as_raw_fd(), &b, object.as_raw_fd(), e);
                if r.is_ok() {
                    row.beside = Some(
                        Path::new(&e.file.path)
                            .with_file_name(&b)
                            .display()
                            .to_string(),
                    );
                }
                r
            }
            Plan::Unchanged | Plan::Refuse(_) => Ok(None),
        };
        match written {
            Ok(after) => row.sha256_after = after,
            Err(err) => return finish(row, "refused", format!("{detail}; writing failed: {err}")),
        }
        let mut detail = detail;
        if plan == Plan::Recreate {
            // The attack's renamed copy of this inode, in the same directory.
            if let Some(found) = find_inode(dir.as_raw_fd(), e.file.dev, e.file.ino) {
                let others = post.iter().any(|p| !in_attack(p.writer));
                if others {
                    detail.push_str(&format!(
                        "; its renamed copy {found} was written by others: left"
                    ));
                } else {
                    match jm.lock().move_to_evidence(dir.as_raw_fd(), &found, e.id) {
                        Ok(to) => row.evidence = Some(to),
                        Err(err) => detail.push_str(&format!(
                            "; its renamed copy {found} could not be moved to the journal ({err}): left"
                        )),
                    }
                }
            }
        }
        finish(row, plan.action(), detail)
    }
}

/// `--pid` without a start names a pid: refuse when the journal holds
/// several processes of that pid.
fn ambiguous<'a>(entries: impl Iterator<Item = &'a Entry>, sel: &Selector) -> Option<String> {
    let pids: Vec<u32> = sel
        .roots
        .iter()
        .filter(|r| r.start == 0)
        .map(|r| r.pid)
        .collect();
    if pids.is_empty() {
        return None;
    }
    let mut starts: std::collections::BTreeMap<u32, std::collections::BTreeSet<u64>> =
        Default::default();
    for e in entries.filter(|e| sel.since_ms.is_none_or(|s| e.taken_at_ms >= s)) {
        for h in e.lineage.iter().chain(std::iter::once(&e.writer)) {
            if pids.contains(&h.pid) && h.start != 0 {
                starts.entry(h.pid).or_default().insert(h.start);
            }
        }
    }
    starts.into_iter().find(|(_, s)| s.len() > 1).map(|(pid, s)| {
        format!(
            "pid {pid} names {} different processes in the journal (starts {:?}): narrow it with --since",
            s.len(),
            s
        )
    })
}

/// The process still runs (same pid and start).
pub fn alive(p: ProcId) -> bool {
    if p.pid == 0 {
        return false;
    }
    match proc_start_ticks(Path::new("/proc"), p.pid) {
        Some(s) => p.start == 0 || s == p.start,
        None => false,
    }
}

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

fn open_dir(p: &Path) -> io::Result<OwnedFd> {
    let c = cstr(&p.to_string_lossy())?;
    // SAFETY: NUL-terminated path.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `openat2(root, rel, O_PATH|O_DIRECTORY, RESOLVE_BENEATH |
/// RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)`: the
/// directory under the scope, no link followed on the way (a directory an
/// attacker swapped for a link to `/etc` is refused).
pub fn open_beneath(root: RawFd, rel: &Path) -> io::Result<OwnedFd> {
    let rel = if rel.as_os_str().is_empty() {
        Path::new(".")
    } else {
        rel
    };
    let c = cstr(&rel.to_string_lossy())?;
    // SAFETY: `open_how` is plain integers; zero is a valid value.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_BENEATH
        | libc::RESOLVE_NO_SYMLINKS
        | libc::RESOLVE_NO_MAGICLINKS
        | libc::RESOLVE_NO_XDEV;
    // SAFETY: valid descriptor, path and open_how of the right size.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root,
            c.as_ptr(),
            &how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn fstatat_nofollow(dir: RawFd, name: &str) -> io::Result<libc::stat> {
    let c = cstr(name)?;
    // SAFETY: zeroed buffer filled by the kernel.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid descriptor, name and buffer.
    if unsafe { libc::fstatat(dir, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

fn open_at(dir: RawFd, name: &str, flags: i32, mode: libc::mode_t) -> io::Result<OwnedFd> {
    let c = cstr(name)?;
    // SAFETY: valid descriptor and name.
    let fd = unsafe {
        libc::openat(
            dir,
            c.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Write the object's content into `dst` (empty): a reflink, else a copy.
fn fill(dst: RawFd, object: RawFd) -> io::Result<()> {
    if super::copy::reflink(object, dst).is_ok() {
        return Ok(());
    }
    let size = super::fanotify::fstat(object)?.st_size.max(0) as u64;
    let mut buf = vec![0u8; 1 << 20];
    let mut off = 0u64;
    while off < size {
        // SAFETY: valid descriptor and buffer.
        let n = unsafe {
            libc::pread(
                object,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                off as i64,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            break;
        }
        let mut done = 0usize;
        while done < n as usize {
            // SAFETY: the slice is within `buf`.
            let w = unsafe {
                libc::pwrite(
                    dst,
                    buf[done..n as usize].as_ptr() as *const libc::c_void,
                    n as usize - done,
                    (off + done as u64) as i64,
                )
            };
            if w < 0 {
                return Err(io::Error::last_os_error());
            }
            done += w as usize;
        }
        off += n as u64;
    }
    Ok(())
}

/// The original's modification time back on `fd` (access time kept).
fn set_mtime(fd: RawFd, mtime_ns: i64) {
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: mtime_ns.div_euclid(1_000_000_000),
            tv_nsec: mtime_ns.rem_euclid(1_000_000_000),
        },
    ];
    // SAFETY: valid descriptor and two timespecs.
    unsafe { libc::futimens(fd, times.as_ptr()) };
}

fn hash_after(fd: RawFd) -> Option<String> {
    sha256_fd(fd).ok()
}

/// Rewrite the same inode with the original content.
fn write_in_place(
    dir: RawFd,
    name: &str,
    cur: &Current,
    object: RawFd,
    e: &Entry,
) -> io::Result<Option<String>> {
    let fd = open_at(dir, name, libc::O_RDWR, 0)?;
    let st = super::fanotify::fstat(fd.as_raw_fd())?;
    if (st.st_dev, st.st_ino) != (cur.dev, cur.ino) {
        return Err(io::Error::other("the file changed under the restore"));
    }
    // SAFETY: valid descriptor.
    if unsafe { libc::ftruncate(fd.as_raw_fd(), 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    fill(fd.as_raw_fd(), object)?;
    // SAFETY: valid descriptor.
    unsafe { libc::fsync(fd.as_raw_fd()) };
    set_mtime(fd.as_raw_fd(), e.file.mtime_ns);
    Ok(hash_after(fd.as_raw_fd()))
}

/// Create `name` new with the original's content, mode and owner.
fn write_new(dir: RawFd, name: &str, object: RawFd, e: &Entry) -> io::Result<Option<String>> {
    let mode = (e.file.mode & 0o7777) as libc::mode_t;
    let fd = open_at(
        dir,
        name,
        libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
        0o600,
    )?;
    if let Err(err) = fill(fd.as_raw_fd(), object) {
        let c = cstr(name)?;
        // SAFETY: valid descriptor and name.
        unsafe { libc::unlinkat(dir, c.as_ptr(), 0) };
        return Err(err);
    }
    // SAFETY: valid descriptor. A failed chown (no CAP_CHOWN) leaves the
    // agent's uid: reported by the caller's hash, not fatal.
    unsafe {
        libc::fchown(fd.as_raw_fd(), e.file.uid, e.file.gid);
        libc::fchmod(fd.as_raw_fd(), mode);
        libc::fsync(fd.as_raw_fd());
    }
    set_mtime(fd.as_raw_fd(), e.file.mtime_ns);
    Ok(hash_after(fd.as_raw_fd()))
}

/// The name of the entry of `dir` with inode (`dev`, `ino`), if any (at
/// most 100 000 entries read).
fn find_inode(dir: RawFd, dev: u64, ino: u64) -> Option<String> {
    let rd = std::fs::read_dir(format!("/proc/self/fd/{dir}")).ok()?;
    for ent in rd.take(100_000).filter_map(|e| e.ok()) {
        let name = ent.file_name().to_str()?.to_string();
        if let Ok(st) = fstatat_nofollow(dir, &name) {
            if st.st_dev == dev && st.st_ino == ino && st.st_mode & libc::S_IFMT == libc::S_IFREG {
                return Some(name);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cow::config::{MarkKind, ScopeConfig};
    use std::os::unix::fs::MetadataExt;

    struct Lab {
        _t: tempfile::TempDir,
        scope: std::path::PathBuf,
        store: Arc<Store>,
    }

    fn lab() -> Lab {
        let t = tempfile::TempDir::new().unwrap();
        let scope = t.path().join("scope");
        std::fs::create_dir(&scope).unwrap();
        let cfg = CowConfig {
            enabled: true,
            scopes: vec![ScopeConfig {
                path: scope.clone(),
                mark: MarkKind::Dirs,
                budget: 1 << 20,
                journal: scope.join(".northnarrow-cow"),
            }],
            ..CowConfig::default()
        };
        let (store, problems) = Store::open(cfg, None);
        assert!(problems.is_empty(), "{problems:?}");
        Lab {
            _t: t,
            scope,
            store,
        }
    }

    const ATTACKER: ProcId = ProcId {
        pid: 4_000_000,
        start: 999_999_999,
    };

    /// What the guard does on a write-open: copy the file as it is now.
    fn journal_file(l: &Lab, name: &str, writer: ProcId) -> Entry {
        let p = l.scope.join(name);
        let f = std::fs::File::open(&p).unwrap();
        let st = crate::cow::fanotify::fstat(f.as_raw_fd()).unwrap();
        let (r, evicted) = l.store.reserve(0, st.st_size as u64).unwrap();
        l.store.forget_objects(&evicted);
        let out = crate::cow::copy::snapshot(
            f.as_raw_fd(),
            &st,
            l.store.objects_fds[0],
            &Journal::object_name(r.object),
            1 << 20,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        );
        let method = match out {
            crate::cow::copy::Snapshot::Reflinked { .. } => Method::Reflink,
            crate::cow::copy::Snapshot::Copied { .. } => Method::Copy,
            other => panic!("{other:?}"),
        };
        let m = std::fs::metadata(&p).unwrap();
        l.store
            .commit(
                r,
                FileState {
                    path: p.display().to_string(),
                    dev: m.dev(),
                    ino: m.ino(),
                    size: m.size(),
                    mtime_ns: m.mtime() * 1_000_000_000 + m.mtime_nsec(),
                    ctime_ns: m.ctime() * 1_000_000_000 + m.ctime_nsec(),
                    mode: m.mode(),
                    uid: m.uid(),
                    gid: m.gid(),
                    btime_ns: crate::cow::fanotify::btime(f.as_raw_fd(), None),
                },
                writer,
                "/home/u/sim.py".into(),
                vec![writer],
                now_ms(),
                method,
            )
            .unwrap()
    }

    fn sel() -> Selector {
        Selector {
            roots: vec![ATTACKER],
            since_ms: None,
        }
    }

    fn by() -> RestoreBy {
        RestoreBy::Admin {
            key_fp: "test".into(),
        }
    }

    #[test]
    fn an_encrypted_and_renamed_tree_comes_back_byte_for_byte() {
        let l = lab();
        std::fs::create_dir(l.scope.join("sub")).unwrap();
        let originals: Vec<(String, Vec<u8>)> = (0..6)
            .map(|i| {
                let name = if i % 2 == 0 {
                    format!("f{i}.txt")
                } else {
                    format!("sub/b{i}.bin")
                };
                let data: Vec<u8> = (0..(5000 + i * 999)).map(|k| (k * 7 + i) as u8).collect();
                std::fs::write(l.scope.join(&name), &data).unwrap();
                (name, data)
            })
            .collect();
        // the attack: copy taken at its open, then rewrite; half renamed
        for (i, (name, data)) in originals.iter().enumerate() {
            journal_file(&l, name, ATTACKER);
            let junk: Vec<u8> = data.iter().map(|b| b ^ 0x5a).collect();
            std::fs::write(l.scope.join(name), &junk).unwrap();
            if i % 2 == 1 {
                std::fs::rename(l.scope.join(name), l.scope.join(format!("{name}.locked")))
                    .unwrap();
            }
        }
        let dry = l.store.restore(&sel(), true, &by());
        assert_eq!(dry.rows.len(), 6);
        assert!(
            dry.rows.iter().all(|r| r.action.starts_with("would_")),
            "{:?}",
            dry.rows
        );
        assert_ne!(
            std::fs::read(l.scope.join("f0.txt")).unwrap(),
            originals[0].1,
            "a dry run changes nothing"
        );
        let rep = l.store.restore(&sel(), false, &by());
        assert_eq!(
            (rep.restored, rep.recreated, rep.kept_both, rep.refused),
            (3, 3, 0, 0),
            "{:?}",
            rep.rows
        );
        for (name, data) in &originals {
            assert_eq!(&std::fs::read(l.scope.join(name)).unwrap(), data, "{name}");
        }
        // the renamed encrypted files went to the journal's evidence
        for (i, (name, _)) in originals.iter().enumerate() {
            assert!(!l.scope.join(format!("{name}.locked")).exists(), "{i}");
        }
        assert!(rep.rows.iter().filter(|r| r.evidence.is_some()).count() == 3);
        assert!(rep
            .rows
            .iter()
            .all(|r| r.sha256_after.as_deref() == Some(r.sha256_original.as_str())));
        // a second restore finds the originals in place
        let again = l.store.restore(&sel(), false, &by());
        assert_eq!(again.unchanged, 6, "{:?}", again.rows);
    }

    #[test]
    fn a_trusted_edit_after_the_attack_keeps_both() {
        let l = lab();
        std::fs::write(l.scope.join("doc.txt"), b"original").unwrap();
        let e = journal_file(&l, "doc.txt", ATTACKER);
        std::fs::write(l.scope.join("doc.txt"), b"encrypted junk").unwrap();
        // the owner edits it afterwards with vim
        l.store.record_post_write(
            e.file.dev,
            e.file.ino,
            PostWrite {
                at_ms: e.taken_at_ms + 10,
                writer: ProcId {
                    pid: 1234,
                    start: 1,
                },
                program: "/usr/bin/vim.basic".into(),
                trusted: true,
            },
        );
        std::fs::write(
            l.scope.join("doc.txt"),
            b"encrypted junk + the owner's edit",
        )
        .unwrap();
        let rep = l.store.restore(&sel(), false, &by());
        assert_eq!(rep.kept_both, 1, "{:?}", rep.rows);
        assert_eq!(
            std::fs::read(l.scope.join("doc.txt")).unwrap(),
            b"encrypted junk + the owner's edit",
            "never overwritten"
        );
        let beside = l.scope.join(format!("doc.txt.nn-restored-{}", e.id));
        assert_eq!(std::fs::read(&beside).unwrap(), b"original");
        assert_eq!(
            rep.rows[0].beside.as_deref(),
            Some(beside.to_str().unwrap())
        );
        assert!(rep.rows[0]
            .detail
            .contains("trusted writer /usr/bin/vim.basic"));
    }

    #[test]
    fn a_corrupted_copy_is_refused_and_a_replaced_file_kept() {
        let l = lab();
        std::fs::write(l.scope.join("a"), b"aaaa").unwrap();
        std::fs::write(l.scope.join("b"), b"bbbb").unwrap();
        let ea = journal_file(&l, "a", ATTACKER);
        journal_file(&l, "b", ATTACKER);
        // root corrupts the copy of a; b is replaced by a new inode
        let obj = l
            .scope
            .join(".northnarrow-cow/objects")
            .join(format!("{:016x}", ea.object));
        std::fs::write(&obj, b"tampered").unwrap();
        std::fs::write(l.scope.join("a"), b"xxxx").unwrap();
        std::fs::remove_file(l.scope.join("b")).unwrap();
        std::fs::write(l.scope.join("b"), b"new file").unwrap();
        let rep = l.store.restore(&sel(), false, &by());
        let row = |p: &str| {
            rep.rows
                .iter()
                .find(|r| r.path.ends_with(p))
                .unwrap()
                .clone()
        };
        assert_eq!(row("/a").action, "refused");
        assert!(row("/a").detail.contains("journal_corrupt"));
        assert_eq!(std::fs::read(l.scope.join("a")).unwrap(), b"xxxx");
        assert_eq!(row("/b").action, "kept_both");
        assert_eq!(std::fs::read(l.scope.join("b")).unwrap(), b"new file");
    }

    #[test]
    fn a_link_in_the_path_is_refused() {
        let l = lab();
        std::fs::create_dir(l.scope.join("d")).unwrap();
        std::fs::write(l.scope.join("d/f"), b"orig").unwrap();
        journal_file(&l, "d/f", ATTACKER);
        // the attacker swaps the directory for a link elsewhere
        let elsewhere = l.scope.parent().unwrap().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::rename(l.scope.join("d"), l.scope.join("d.old")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, l.scope.join("d")).unwrap();
        let rep = l.store.restore(&sel(), false, &by());
        assert_eq!(rep.rows[0].action, "refused", "{:?}", rep.rows);
        assert!(
            !elsewhere.join("f").exists(),
            "nothing written through the link"
        );
    }

    #[test]
    fn selection_and_ambiguity() {
        let l = lab();
        std::fs::write(l.scope.join("a"), b"a").unwrap();
        std::fs::write(l.scope.join("b"), b"b").unwrap();
        journal_file(&l, "a", ATTACKER);
        journal_file(
            &l,
            "b",
            ProcId {
                pid: ATTACKER.pid,
                start: 5,
            },
        );
        let rep = l.store.restore(
            &Selector {
                roots: vec![ProcId {
                    pid: ATTACKER.pid,
                    start: 0,
                }],
                since_ms: None,
            },
            true,
            &by(),
        );
        assert!(
            rep.refusal
                .as_deref()
                .unwrap_or("")
                .contains("2 different processes"),
            "{rep:?}"
        );
        let rep = l.store.restore(
            &Selector {
                roots: vec![ProcId { pid: 1, start: 7 }],
                since_ms: None,
            },
            true,
            &by(),
        );
        assert_eq!(
            rep.refusal.as_deref(),
            Some("no copy in the journal matches")
        );
        let rep = l.store.restore(
            &Selector {
                roots: vec![],
                since_ms: Some(0),
            },
            true,
            &by(),
        );
        assert_eq!(rep.rows.len(), 2);
    }

    #[test]
    fn the_index_survives_a_restart_and_an_old_copy_is_not_overwritten_blind() {
        let l = lab();
        std::fs::write(l.scope.join("a"), b"original").unwrap();
        journal_file(&l, "a", ATTACKER);
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(l.scope.join("a"), b"junk").unwrap();
        let cfg = l.store.cfg.clone();
        drop(l.store);
        let (store, problems) = Store::open(cfg, None);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(store.index.lock().entry_count(0), 1);
        let rep = store.restore(&sel(), false, &by());
        assert_eq!(rep.kept_both, 1, "{:?}", rep.rows);
        assert_eq!(std::fs::read(l.scope.join("a")).unwrap(), b"junk");
    }

    #[test]
    fn counters_are_named() {
        let s = Stats::default();
        s.answered(true, 40);
        s.answered(true, 60);
        let snap = s.snapshot();
        let get = |n: &str| snap.iter().find(|(k, _)| k == n).unwrap().1;
        assert_eq!(get("answer_copy_count"), 2);
        assert_eq!(get("answer_copy_us_total"), 100);
        assert_eq!(get("answer_copy_us_max"), 60);
        assert_eq!(get("copies_reflink"), 0);
    }
}
