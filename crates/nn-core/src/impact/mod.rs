//! Lab PR 225 (countermeasure CM-16): the decisive ransomware signal.
//!
//! Four shapes of one process tree's file activity, each counted in the
//! kernel or measured on what it left behind:
//!
//! - **(a) rewrites** — the overwrite crossing of the mass-write counter
//!   (`Event::MassWrite { overwrites: true }`: 20 existing files of at
//!   least 4 KiB opened for writing in 60 s by one process, or 40 by one
//!   cgroup's);
//! - **(b) entropy** — what (a) or (c) left behind is ciphertext-like
//!   ([`entropy`]: high entropy, no format header, in two files or more of
//!   up to four; for copies, the copies themselves, never the originals
//!   still waiting beside them);
//! - **(c) renames to a new extension** — the rename burst
//!   (`Event::FileBurst { kind: RenameExtension }`: 20 renames to one new
//!   extension in 60 s) when its shape is an encryptor's — mostly appended
//!   (`a.pdf` → `a.pdf.locked`), originals of different kinds, or an
//!   extension of NN-L-FIM-010's list — or encrypted copies under an
//!   extension appended to the names of the originals (d) deleted, found
//!   beside them;
//! - **(d) deletion of originals after writing new files** — the unlink
//!   burst (`Event::FileBurst { kind: Unlink }`: 20 files of at least 4 KiB
//!   in 60 s) of an actor that crossed the new-file mass-write threshold in
//!   the window.
//!
//! Any **two** of them within [`RANSOM_WINDOW_NS`] for one actor make the
//! assessment **decisive**: NN-L-IMP-001 (Critical, `KillProcessTree` of the
//! actor) and the posture's `RansomwareEncryption` (COMBAT without
//! corroboration, not locked) — both held behind the per-rule response
//! policy, off by default (decision of 21/10/2026): a Critical record, and
//! a trigger that needs corroboration. One shape alone keeps the level it had: the
//! mass-write arm of the posture for (a), a record for (c) (NN-L-IMP-002),
//! nothing for (d) — `rm -rf`, a cache sweep.
//!
//! Signals are counted only for writers whose trust is not established
//! ([`trust`]): a package transaction, or a packaged program with a lineage
//! of installed programs (`rsync`, `tar`, `git`, a compiler, a packaged
//! backup agent or database), never counts. The actor is the nearest
//! foreign program of the writer's lineage (a script's `mv` and `rm` count
//! against the script), or the writer.
//!
//! The assessment of one event is memoised: the posture (which reads the
//! event first) and the rule engine see the same answer, and the files are
//! sampled once.

pub mod entropy;
pub mod trust;

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nn_model::{Event, FileBurstKind};
use parking_lot::Mutex;

use crate::decision::host::DecisionHost;
use crate::posture::lineage::AuthSessionTracker;
use entropy::Sampler;
use trust::{Judged, ProgramOwners};

/// The window in which two shapes of one actor combine: two kernel windows.
/// A burst re-crosses its threshold once per kernel window while it lasts,
/// so a long encryption keeps its shapes fresh.
pub const RANSOM_WINDOW_NS: u64 = 2 * common::wire::open_sensor::OPEN_BURST_WINDOW_NS;

/// Distinct shapes that make the assessment decisive.
pub const DECISIVE_SHAPES: usize = 2;

/// Actors tracked at once; the stalest goes first.
const ACTORS_CAP: usize = 256;
/// Assessments remembered by event.
const MEMO_CAP: usize = 64;
/// Recent new-file crossings kept per actor (for (d) and the copies of (c)).
const NEW_FILES_CAP: usize = 8;
/// Samplings per actor per window (each reads at most four files).
const SAMPLES_PER_WINDOW: u32 = 4;

/// A shape of ransomware activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Signal {
    /// (a) rewrites of existing files.
    Rewrites,
    /// (b) ciphertext-like content left behind.
    Entropy,
    /// (c) renames, or copies, to one new extension.
    RenameExtension,
    /// (d) deletion of originals after writing new files.
    DeleteOriginals,
}

impl Signal {
    pub fn as_str(self) -> &'static str {
        match self {
            Signal::Rewrites => "rewrites of existing files",
            Signal::Entropy => "ciphertext-like content",
            Signal::RenameExtension => "renames to a new extension",
            Signal::DeleteOriginals => "deletion of originals after writing new files",
        }
    }
}

/// What the tracker made of one event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// The process the event names.
    pub writer: u32,
    /// The process a kill targets: the nearest foreign program of the
    /// writer's lineage, or the writer (a pid).
    pub actor: u32,
    /// The process the shapes add up under: the writer, or the payload whose
    /// forked worker it is.
    pub key: u32,
    /// The actor's program.
    pub program: String,
    /// `Some`: the writer is trusted (why); no signal counted.
    pub trusted: Option<String>,
    /// The actor's shapes in the window, each with what showed it.
    pub signals: Vec<(Signal, String)>,
    /// The shapes this event added.
    pub added: Vec<Signal>,
    /// Two shapes or more.
    pub decisive: bool,
    /// The event is a rename burst of an encryptor's shape (NN-L-IMP-002's
    /// single-signal record).
    pub rename_burst: bool,
    /// Why the writer is judged (when it is).
    pub why: String,
}

impl Assessment {
    /// One line for a verdict: the shapes and what showed them.
    pub fn describe(&self) -> String {
        self.signals
            .iter()
            .map(|(s, d)| format!("{} ({d})", s.as_str()))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Counters for `status` (appended to `StatusResponse`).
#[derive(Debug, Default)]
pub struct RansomCounters {
    /// Assessments that became decisive (one per actor and window).
    pub decisive: AtomicU64,
    /// Shapes counted toward an actor.
    pub signals: AtomicU64,
    /// Bursts of trusted writers, not counted.
    pub trusted: AtomicU64,
    /// Entropy samplings run.
    pub samplings: AtomicU64,
}

/// A snapshot of [`RansomCounters`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RansomCounts {
    pub decisive: u64,
    pub signals: u64,
    pub trusted: u64,
    pub samplings: u64,
}

#[derive(Debug, Default)]
struct ActorWindow {
    program: String,
    /// Shape → (last time, what showed it).
    seen: HashMap<Signal, (u64, String)>,
    /// New-file mass-write crossings: (time, file).
    new_files: VecDeque<(u64, String)>,
    /// Samplings run in the current window, and when the window started.
    samplings: u32,
    sampling_window: u64,
    /// When the actor last became decisive (counted once per window).
    decisive_at: Option<u64>,
    last: u64,
}

#[derive(Default)]
struct State {
    actors: HashMap<u32, ActorWindow>,
    memo: VecDeque<((u32, u64, u8), Arc<Assessment>)>,
}

/// The tracker the posture and the rules share.
pub struct RansomTracker<H: DecisionHost> {
    lineage: AuthSessionTracker<H>,
    owners: ProgramOwners<H>,
    sampler: Arc<dyn Sampler>,
    state: Mutex<State>,
    counters: RansomCounters,
}

impl<H: DecisionHost> RansomTracker<H> {
    /// Production: the host's package database and files.
    pub fn new(lineage: AuthSessionTracker<H>) -> Self {
        Self::with(lineage, ProgramOwners::default(), H::sampler())
    }

    /// With a package database root and a sampler of its own (tests).
    pub fn with(
        lineage: AuthSessionTracker<H>,
        owners: ProgramOwners<H>,
        sampler: Arc<dyn Sampler>,
    ) -> Self {
        Self {
            lineage,
            owners,
            sampler,
            state: Mutex::new(State::default()),
            counters: RansomCounters::default(),
        }
    }

    pub fn counts(&self) -> RansomCounts {
        RansomCounts {
            decisive: self.counters.decisive.load(Ordering::Relaxed),
            signals: self.counters.signals.load(Ordering::Relaxed),
            trusted: self.counters.trusted.load(Ordering::Relaxed),
            samplings: self.counters.samplings.load(Ordering::Relaxed),
        }
    }

    /// The assessment of `event`: `None` for an event that is no burst.
    pub fn assess(&self, event: &Event) -> Option<Arc<Assessment>> {
        let (pid, ts, tag) = match event {
            Event::MassWrite {
                pid,
                timestamp_ns,
                overwrites,
                ..
            } => (*pid, *timestamp_ns, u8::from(*overwrites)),
            Event::FileBurst {
                pid,
                timestamp_ns,
                kind,
                ..
            } => (
                *pid,
                *timestamp_ns,
                match kind {
                    FileBurstKind::RenameExtension => 2,
                    FileBurstKind::Unlink => 3,
                },
            ),
            _ => return None,
        };
        let key = (pid, ts, tag);
        if let Some((_, a)) = self.state.lock().memo.iter().find(|(k, _)| *k == key) {
            return Some(Arc::clone(a));
        }
        let a = Arc::new(self.judge(event, pid, ts));
        let mut st = self.state.lock();
        if st.memo.len() >= MEMO_CAP {
            st.memo.pop_front();
        }
        st.memo.push_back((key, Arc::clone(&a)));
        Some(a)
    }

    fn judge(&self, event: &Event, pid: u32, ts: u64) -> Assessment {
        let lineage = self.lineage.lineage_identities(pid);
        let package_tx = self.lineage.in_package_transaction(pid, ts);
        let owned = |p: &std::path::Path| self.owners.owned(p);
        let mut a = Assessment {
            writer: pid,
            actor: pid,
            key: pid,
            program: String::new(),
            trusted: None,
            signals: Vec::new(),
            added: Vec::new(),
            decisive: false,
            rename_burst: false,
            why: String::new(),
        };
        match trust::judge(pid, lineage.as_deref(), package_tx, &owned) {
            Judged::Trusted(t) => {
                self.counters.trusted.fetch_add(1, Ordering::Relaxed);
                a.trusted = Some(t.describe());
                a.program = match t {
                    trust::Trusted::PackagedProgram(p) => p,
                    trust::Trusted::PackageTransaction => String::new(),
                };
                return a;
            }
            Judged::Untrusted {
                actor,
                key,
                program,
                why,
            } => {
                a.actor = actor;
                a.key = key;
                a.program = program;
                a.why = why;
            }
        }
        // What this event shows, and the files to sample for (b).
        let mut shapes: Vec<(Signal, String)> = Vec::new();
        let mut sample: Option<String> = None;
        let mut copies_of: Option<(String, Vec<String>, u32)> = None;
        match event {
            Event::MassWrite {
                overwrites: true,
                count,
                filename,
                cgroup_window,
                ..
            } => {
                shapes.push((
                    Signal::Rewrites,
                    format!(
                        "{count} existing files rewritten in 60 s{}, last {filename}",
                        if *cgroup_window {
                            " by the processes of one cgroup"
                        } else {
                            ""
                        }
                    ),
                ));
                sample = Some(filename.clone());
            }
            Event::MassWrite {
                overwrites: false,
                filename,
                ..
            } => {
                let mut st = self.state.lock();
                let w = actor_window(&mut st, a.key, &a.program, ts);
                if w.new_files.len() >= NEW_FILES_CAP {
                    w.new_files.pop_front();
                }
                w.new_files.push_back((ts, filename.clone()));
            }
            Event::FileBurst {
                kind: FileBurstKind::RenameExtension,
                count,
                appended,
                sources,
                filename,
                ..
            } => {
                let listed = crate::fim::rules::has_ransomware_extension(filename);
                let shaped = appended.saturating_mul(2) >= *count || *sources >= 3 || listed;
                if shaped {
                    a.rename_burst = true;
                    shapes.push((
                        Signal::RenameExtension,
                        format!(
                            "{count} files renamed to .{} in 60 s ({appended} appended, \
                             {sources} changes of the original extension), last {filename}",
                            extension(filename).unwrap_or("?")
                        ),
                    ));
                    sample = Some(filename.clone());
                }
            }
            Event::FileBurst {
                kind: FileBurstKind::Unlink,
                count,
                filename,
                uid,
                ..
            } => {
                let mut st = self.state.lock();
                let w = actor_window(&mut st, a.key, &a.program, ts);
                let new: Vec<String> = w
                    .new_files
                    .iter()
                    .filter(|(t, _)| t.abs_diff(ts) <= RANSOM_WINDOW_NS)
                    .map(|(_, f)| f.clone())
                    .collect();
                drop(st);
                if !new.is_empty() {
                    shapes.push((
                        Signal::DeleteOriginals,
                        format!(
                            "{count} files of 4 KiB or more deleted in 60 s after {} new files \
                             were written, last {filename}",
                            common::wire::open_sensor::OPEN_MASS_WRITE_MIN
                        ),
                    ));
                    copies_of = Some((filename.clone(), new, *uid));
                }
            }
            _ => {}
        }
        // (c) by copies: the deleted original's name with an extension
        // appended (`a.pdf` → `a.pdf.locked`) is there now, and the copies
        // of that shape — whose originals are gone — hold ciphertext-like
        // content: (b) on the copies themselves, never on the originals
        // still waiting beside them (lab, MS-23 copy-delete). A copy of
        // plain content is a backup, a compressed one a rotation: not
        // counted. In a directory shared by everyone (`/tmp`) only the
        // copies of the uid the burst ran as count (lab PR 238).
        let mut copy_checked = false;
        if let Some((deleted, new, uid)) = &copies_of {
            if let Some((copy, suffix)) = copy_beside::<H>(deleted, new) {
                copy_checked = true;
                self.counters.samplings.fetch_add(1, Ordering::Relaxed);
                let s = self.sampler.sample_copies_by(
                    &copy,
                    &suffix,
                    *uid,
                    Duration::from_nanos(RANSOM_WINDOW_NS),
                );
                if s.holds() {
                    shapes.push((
                        Signal::RenameExtension,
                        format!(
                            "encrypted copies under a new extension (.{suffix}) beside the \
                             originals deleted, e.g. {copy}"
                        ),
                    ));
                    shapes.push((
                        Signal::Entropy,
                        format!(
                            "{} of {} copies under .{suffix} whose originals are gone \
                             high-entropy with no format header",
                            s.high, s.examined
                        ),
                    ));
                }
            }
        }
        if copy_checked {
            sample = None;
        }
        let mut st = self.state.lock();
        let w = actor_window(&mut st, a.key, &a.program, ts);
        let want_sample = sample.is_some()
            && !w
                .seen
                .get(&Signal::Entropy)
                .is_some_and(|(t, _)| t.abs_diff(ts) <= RANSOM_WINDOW_NS);
        if ts.abs_diff(w.sampling_window) > RANSOM_WINDOW_NS {
            w.sampling_window = ts;
            w.samplings = 0;
        }
        let may_sample = want_sample && w.samplings < SAMPLES_PER_WINDOW;
        if may_sample {
            w.samplings += 1;
        }
        drop(st);
        if let (true, Some(path)) = (may_sample, &sample) {
            self.counters.samplings.fetch_add(1, Ordering::Relaxed);
            let s = self
                .sampler
                .sample(path, Duration::from_nanos(RANSOM_WINDOW_NS));
            if s.holds() {
                shapes.push((
                    Signal::Entropy,
                    format!(
                        "{} of {} files beside {path} high-entropy with no format header",
                        s.high, s.examined
                    ),
                ));
            }
        }
        let mut st = self.state.lock();
        let w = actor_window(&mut st, a.key, &a.program, ts);
        for (s, d) in shapes {
            if !a.added.contains(&s) {
                a.added.push(s);
            }
            w.seen.insert(s, (ts, d));
            self.counters.signals.fetch_add(1, Ordering::Relaxed);
        }
        let mut present: Vec<(Signal, String)> = w
            .seen
            .iter()
            .filter(|(_, (t, _))| t.abs_diff(ts) <= RANSOM_WINDOW_NS)
            .map(|(s, (_, d))| (*s, d.clone()))
            .collect();
        present.sort_by_key(|(s, _)| *s);
        a.decisive = present.len() >= DECISIVE_SHAPES;
        if a.decisive
            && !w
                .decisive_at
                .is_some_and(|t| t.abs_diff(ts) <= RANSOM_WINDOW_NS)
        {
            w.decisive_at = Some(ts);
            self.counters.decisive.fetch_add(1, Ordering::Relaxed);
        }
        a.signals = present;
        a
    }
}

/// The window of `actor`, a fresh one for a pid that now runs another
/// program (reused), the stalest actor evicted at the bound.
fn actor_window<'a>(st: &'a mut State, actor: u32, program: &str, ts: u64) -> &'a mut ActorWindow {
    if st.actors.len() >= ACTORS_CAP && !st.actors.contains_key(&actor) {
        let stale: Vec<u32> = st
            .actors
            .iter()
            .filter(|(_, w)| w.last.abs_diff(ts) > RANSOM_WINDOW_NS)
            .map(|(p, _)| *p)
            .collect();
        for p in stale {
            st.actors.remove(&p);
        }
        if st.actors.len() >= ACTORS_CAP {
            if let Some(p) = st
                .actors
                .iter()
                .min_by_key(|(_, w)| w.last)
                .map(|(p, _)| *p)
            {
                st.actors.remove(&p);
            }
        }
    }
    let w = st.actors.entry(actor).or_default();
    if w.program != program {
        *w = ActorWindow {
            program: program.to_string(),
            ..Default::default()
        };
    }
    w.last = w.last.max(ts);
    w
}

/// The extension of a file name (the bytes after its last dot); none for
/// a hidden name with no other dot, or digits only (a rotation).
fn extension(path: &str) -> Option<&str> {
    let name = path.rsplit('/').next()?;
    let (stem, ext) = name.rsplit_once('.')?;
    (!stem.is_empty() && !ext.is_empty() && !ext.bytes().all(|b| b.is_ascii_digit())).then_some(ext)
}

/// A copy of `deleted` beside it under its own name with an extension
/// appended (`a.pdf` → `a.pdf.locked`, `a.pdf.id-7.[x@y].wallet`), there
/// now: the encrypt-into-a-new-file-then-delete variant. The extension of
/// one of the `new` files is tried first; else the directory is looked
/// through for `<name>.<anything>` (the burst's crossing write-open may have
/// been a ransom note, not a copy), the newest such file. Returns the copy
/// and the appended part. A replaced extension (`x.c` → `x.o`) is what a
/// build leaves, not looked for.
fn copy_beside<H: DecisionHost>(deleted: &str, new: &[String]) -> Option<(String, String)> {
    if !deleted.starts_with('/') {
        return None;
    }
    let (dir, name) = deleted.rsplit_once('/')?;
    if name.is_empty() {
        return None;
    }
    let mut exts: Vec<&str> = new.iter().filter_map(|n| extension(n)).collect();
    exts.sort_unstable();
    exts.dedup();
    let found = exts.into_iter().find(|ext| {
        H::on_host_path(std::path::Path::new(&format!("{dir}/{name}.{ext}")), |p| {
            std::fs::symlink_metadata(p)
        })
        .is_ok_and(|m| m.is_file())
    });
    if let Some(ext) = found {
        return Some((format!("{dir}/{name}.{ext}"), ext.to_string()));
    }
    let prefix = format!("{name}.");
    let parent = if dir.is_empty() { "/" } else { dir };
    let newest = H::on_host_path(std::path::Path::new(parent), |p| {
        let mut best: Option<(std::time::SystemTime, String)> = None;
        for e in std::fs::read_dir(p)?.take(entropy::COPY_SCAN_MAX).flatten() {
            let leaf = e.file_name();
            let Some(suffix) = leaf.to_str().and_then(|l| l.strip_prefix(prefix.as_str())) else {
                continue;
            };
            if suffix.is_empty() || !e.file_type().is_ok_and(|t| t.is_file()) {
                continue;
            }
            let at = e
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            if best.as_ref().is_none_or(|(t, _)| at > *t) {
                best = Some((at, suffix.to_string()));
            }
        }
        Ok(best)
    })
    .ok()
    .flatten()?;
    Some((format!("{dir}/{name}.{}", newest.1), newest.1))
}

#[cfg(test)]
mod tests;
