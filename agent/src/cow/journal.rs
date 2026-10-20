//! A scope's journal on disk.
//!
//! ```text
//! <journal>/              0700 root   MUTATE | NOCREATE (anti-tamper)
//! <journal>/objects/<id>  0600 root   the copies (MUTATE | NOCREATE on the directory)
//! <journal>/evidence/     0700 root   encrypted files moved aside by a restore
//! <journal>/index.jsonl   0600 root   MUTATE | WRITE: the content index
//! ```
//!
//! Everything is reached through the host's mount namespace
//! (`/proc/1/root`): the agent's own view is read-only outside its state
//! directories, and a reflink needs the object on the mount the writer
//! opened the file through. The directories are registered in the kernel's
//! `PROTECTED_INODES` with the flags of the agent's own directories: no
//! process outside the agent's family (outside a trusted-installer window)
//! may create, unlink or rename an entry in them, so root cannot delete the
//! copies; `index.jsonl` refuses write-opens too. The objects themselves
//! are not registered one by one (the map has 1024 slots for the whole
//! agent): a root process could still open one for writing — its SHA-256 in
//! the index then no longer matches and the restore refuses it
//! (`journal_corrupt`) instead of writing it back.

use std::ffi::CString;
use std::io::{self, Write as _};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::index::{Entry, JournalIndex, Method, ObjectInfo};

/// One line of `index.jsonl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Record {
    Object {
        id: u64,
        bytes: u64,
        method: Method,
        taken_at_ms: u64,
    },
    Entry {
        entry: Box<Entry>,
    },
    Drop {
        object: u64,
    },
}

/// The host's view of `p` when the agent can reach it (`/proc/1/root`),
/// else `p` (tests, a run without `CAP_SYS_PTRACE`).
pub fn host_view(p: &Path) -> PathBuf {
    static REACHABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *REACHABLE.get_or_init(|| std::fs::metadata("/proc/1/root/").is_ok()) {
        crate::response::host_path(p)
    } else {
        p.to_path_buf()
    }
}

fn open_dir(p: &Path) -> io::Result<OwnedFd> {
    let c = CString::new(p.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: NUL-terminated path.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Create `p` 0700, or check the existing one: a directory (not a link)
/// owned by the agent's uid with no group or other access.
fn ensure_private_dir(p: &Path) -> Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(m) => {
            if !m.file_type().is_dir() {
                bail!(
                    "{} exists and is not a directory (or is a link)",
                    p.display()
                );
            }
            // SAFETY: geteuid has no preconditions.
            let me = unsafe { libc::geteuid() };
            if m.uid() != me {
                bail!(
                    "{} is owned by uid {} — refusing a journal another user could have planted",
                    p.display(),
                    m.uid()
                );
            }
            if m.mode() & 0o077 != 0 {
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
                    .with_context(|| format!("chmod 0700 {}", p.display()))?;
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => std::fs::DirBuilder::new()
            .mode(0o700)
            .create(p)
            .with_context(|| format!("mkdir {}", p.display())),
        Err(e) => Err(e).with_context(|| format!("stat {}", p.display())),
    }
}

/// A scope's journal, open.
pub struct Journal {
    /// The configured path (logs, status).
    pub path: PathBuf,
    /// The host's view of it.
    host: PathBuf,
    root: OwnedFd,
    objects: OwnedFd,
    evidence: OwnedFd,
    index: std::fs::File,
    /// Lines in `index.jsonl` (compaction).
    lines: u64,
}

impl Journal {
    /// Open (create) the journal at `path`, whose parent must exist.
    pub fn open(path: &Path) -> Result<Self> {
        let host = host_view(path);
        let parent = host
            .parent()
            .ok_or_else(|| anyhow!("journal {} has no parent", path.display()))?;
        if !parent.is_dir() {
            bail!(
                "the directory above journal {} does not exist",
                path.display()
            );
        }
        ensure_private_dir(&host)?;
        ensure_private_dir(&host.join("objects"))?;
        ensure_private_dir(&host.join("evidence"))?;
        let root = open_dir(&host).with_context(|| format!("open {}", host.display()))?;
        let objects = open_dir(&host.join("objects"))?;
        let evidence = open_dir(&host.join("evidence"))?;
        let index = Self::open_index(&root)?;
        let lines = std::fs::read(host.join("index.jsonl"))
            .map(|b| b.iter().filter(|c| **c == b'\n').count() as u64)
            .unwrap_or(0);
        Ok(Self {
            path: path.to_path_buf(),
            host,
            root,
            objects,
            evidence,
            index,
            lines,
        })
    }

    fn open_index(root: &OwnedFd) -> Result<std::fs::File> {
        let name = CString::new("index.jsonl").unwrap_or_default();
        // SAFETY: valid directory descriptor and name.
        let fd = unsafe {
            libc::openat(
                root.as_raw_fd(),
                name.as_ptr(),
                libc::O_CREAT
                    | libc::O_APPEND
                    | libc::O_WRONLY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("open index.jsonl");
        }
        // SAFETY: fresh descriptor.
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    /// The directory the objects are created in.
    pub fn objects_fd(&self) -> RawFd {
        self.objects.as_raw_fd()
    }

    pub fn root_fd(&self) -> RawFd {
        self.root.as_raw_fd()
    }

    pub fn evidence_fd(&self) -> RawFd {
        self.evidence.as_raw_fd()
    }

    /// The host-view paths whose inodes the anti-tamper map protects:
    /// the three directories, then `index.jsonl`.
    pub fn protected_paths(&self) -> (Vec<PathBuf>, PathBuf) {
        (
            vec![
                self.host.clone(),
                self.host.join("objects"),
                self.host.join("evidence"),
            ],
            self.host.join("index.jsonl"),
        )
    }

    /// The device of the journal's filesystem.
    pub fn dev(&self) -> Option<u64> {
        std::fs::metadata(&self.host).ok().map(|m| m.dev())
    }

    pub fn object_name(id: u64) -> CString {
        CString::new(format!("{id:016x}")).unwrap_or_default()
    }

    /// Append records (one write per line).
    pub fn append(&mut self, records: &[Record]) -> Result<()> {
        for r in records {
            let mut line = serde_json::to_vec(r)?;
            line.push(b'\n');
            self.index.write_all(&line).context("append index.jsonl")?;
            self.lines += 1;
        }
        Ok(())
    }

    pub fn sync(&self) {
        let _ = self.index.sync_data();
    }

    /// Read `index.jsonl` back into `ix` as scope `scope`. Returns the
    /// lines that did not parse (reported, skipped).
    pub fn replay(&self, ix: &mut JournalIndex, scope: usize) -> Result<usize> {
        let text = match std::fs::read_to_string(self.host.join("index.jsonl")) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e).context("read index.jsonl"),
        };
        let mut objects: std::collections::BTreeMap<u64, ObjectInfo> = Default::default();
        let mut entries: Vec<Entry> = Vec::new();
        let mut bad = 0usize;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            match serde_json::from_str::<Record>(line) {
                Ok(Record::Object {
                    id,
                    bytes,
                    method,
                    taken_at_ms,
                }) => {
                    objects.insert(
                        id,
                        ObjectInfo {
                            scope,
                            bytes,
                            method,
                            taken_at_ms,
                            used_at_ms: taken_at_ms,
                            refs: 0,
                        },
                    );
                }
                Ok(Record::Entry { entry }) => entries.push(*entry),
                Ok(Record::Drop { object }) => {
                    objects.remove(&object);
                    entries.retain(|e| e.object != object);
                }
                Err(_) => bad += 1,
            }
        }
        let on_disk = self.list_objects();
        for (id, info) in objects {
            if on_disk.contains(&id) {
                ix.restore_object(id, info);
            }
        }
        for mut e in entries {
            e.scope = scope;
            ix.restore_entry(e);
        }
        Ok(bad)
    }

    /// The object ids present in `objects/`.
    pub fn list_objects(&self) -> std::collections::BTreeSet<u64> {
        std::fs::read_dir(self.host.join("objects"))
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter_map(|e| u64::from_str_radix(e.file_name().to_str()?, 16).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn remove_object(&self, id: u64) {
        let name = Self::object_name(id);
        // SAFETY: valid directory descriptor and name.
        unsafe { libc::unlinkat(self.objects.as_raw_fd(), name.as_ptr(), 0) };
    }

    pub fn open_object(&self, id: u64) -> io::Result<OwnedFd> {
        Self::open_object_in(&self.objects, id)
    }

    /// A descriptor of the objects directory (a duplicate: no open), to open
    /// a copy with [`Self::open_object_in`] once this journal's lock is
    /// released. Review of lab PR 222: on a scope marked by mount or by
    /// filesystem the journal lies under the marks, so the guard's own open
    /// of a copy is a permission event its fanotify reader must answer — and
    /// the reader may be waiting for this journal's lock. No journal file is
    /// opened with the journal's or the index's lock held.
    pub fn objects_dir(&self) -> io::Result<OwnedFd> {
        self.objects.try_clone()
    }

    /// Open copy `id` in `objects` (from [`Self::objects_dir`]).
    pub fn open_object_in(objects: &OwnedFd, id: u64) -> io::Result<OwnedFd> {
        let name = Self::object_name(id);
        // SAFETY: valid directory descriptor and name.
        let fd = unsafe {
            libc::openat(
                objects.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fresh descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Rewrite `index.jsonl` with `records` only (a new file renamed over
    /// the old one; its inode is new: the caller registers it again).
    pub fn compact(&mut self, records: &[Record]) -> Result<()> {
        let f = Self::compaction_file(&self.host)?;
        self.compact_into(f, records)
    }

    /// The journal's directory, host view.
    pub fn host(&self) -> &Path {
        &self.host
    }

    /// Create the file a compaction of the journal at `host` writes
    /// (`index.jsonl.new`, appending), before any lock is taken: the open is
    /// a permission event on a scope marked by mount or filesystem
    /// ([`Self::objects_dir`]).
    pub fn compaction_file(host: &Path) -> Result<std::fs::File> {
        let tmp = host.join("index.jsonl.new");
        let _ = std::fs::remove_file(&tmp);
        let f = std::fs::OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(&tmp)
            .context("create index.jsonl.new")?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        Ok(f)
    }

    /// [`Self::compact`] into `f` (from [`Self::compaction_file`]), which
    /// becomes the index without being opened again.
    pub fn compact_into(&mut self, mut f: std::fs::File, records: &[Record]) -> Result<()> {
        for r in records {
            let mut line = serde_json::to_vec(r)?;
            line.push(b'\n');
            f.write_all(&line)?;
        }
        f.sync_all()?;
        std::fs::rename(
            self.host.join("index.jsonl.new"),
            self.host.join("index.jsonl"),
        )
        .context("rename index.jsonl")?;
        self.index = f;
        self.lines = records.len() as u64;
        Ok(())
    }

    /// Lines in `index.jsonl`.
    pub fn lines(&self) -> u64 {
        self.lines
    }

    /// Move `name` of directory `dir` into `evidence/` as `<tag>-<name>`
    /// (a rename: same filesystem only).
    pub fn move_to_evidence(&self, dir: RawFd, name: &str, tag: u64) -> io::Result<String> {
        let from = CString::new(name).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        let safe: String = name
            .chars()
            .map(|c| if c == '/' { '_' } else { c })
            .collect();
        let to_name = format!("{tag}-{safe}");
        let to = CString::new(to_name.clone())
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        // SAFETY: valid descriptors and names.
        let rc =
            unsafe { libc::renameat(dir, from.as_ptr(), self.evidence.as_raw_fd(), to.as_ptr()) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(self
            .path
            .join("evidence")
            .join(to_name)
            .display()
            .to_string())
    }

    /// Delete evidence files older than `cutoff` (Unix seconds).
    pub fn expire_evidence(&self, cutoff_secs: i64) {
        if let Ok(rd) = std::fs::read_dir(self.host.join("evidence")) {
            for e in rd.filter_map(|e| e.ok()) {
                if e.metadata().is_ok_and(|m| m.mtime() < cutoff_secs) {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cow::index::FileState;
    use crate::cow::trust::ProcId;

    fn entry(id: u64, object: u64) -> Entry {
        Entry {
            id,
            object,
            scope: 3,
            file: FileState {
                path: "/srv/t/a".into(),
                dev: 1,
                ino: 2,
                size: 5,
                mtime_ns: 1,
                ctime_ns: 1,
                mode: 0o100644,
                uid: 1000,
                gid: 1000,
                btime_ns: None,
            },
            sha256: "00".into(),
            writer: ProcId { pid: 9, start: 1 },
            writer_program: "x".into(),
            lineage: vec![],
            taken_at_ms: 10,
            method: Method::Copy,
        }
    }

    #[test]
    fn a_journal_is_private_and_replays() {
        let t = tempfile::TempDir::new().unwrap();
        let p = t.path().join(".northnarrow-cow");
        let mut j = Journal::open(&p).unwrap();
        for d in ["", "objects", "evidence"] {
            let m = std::fs::metadata(p.join(d)).unwrap();
            assert_eq!(m.mode() & 0o777, 0o700, "{d}");
        }
        // an object file and its records; one dropped, one orphan file
        for id in [1u64, 2, 3] {
            std::fs::write(p.join("objects").join(format!("{id:016x}")), b"hello").unwrap();
        }
        j.append(&[
            Record::Object {
                id: 1,
                bytes: 5,
                method: Method::Copy,
                taken_at_ms: 10,
            },
            Record::Entry {
                entry: Box::new(entry(1, 1)),
            },
            Record::Object {
                id: 2,
                bytes: 5,
                method: Method::Copy,
                taken_at_ms: 10,
            },
            Record::Entry {
                entry: Box::new(entry(2, 2)),
            },
            Record::Drop { object: 2 },
        ])
        .unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(p.join("index.jsonl"))
            .unwrap()
            .write_all(b"{not json\n")
            .unwrap();
        let mut ix = JournalIndex::new(&[1000], u64::MAX, 0);
        let bad = j.replay(&mut ix, 0).unwrap();
        assert_eq!(bad, 1);
        assert_eq!(ix.entry_count(0), 1);
        assert_eq!(
            ix.entry(1).unwrap().scope,
            0,
            "the scope is the current one"
        );
        assert_eq!(ix.usage(0).unwrap().used, 5);
        assert_eq!(j.list_objects().len(), 3);
        // reopen: same files, the line count read back
        let j2 = Journal::open(&p).unwrap();
        assert_eq!(j2.lines(), 6);
        // compaction keeps what is passed
        let mut j3 = j2;
        j3.compact(&[Record::Drop { object: 9 }]).unwrap();
        assert_eq!(
            std::fs::read_to_string(p.join("index.jsonl"))
                .unwrap()
                .lines()
                .count(),
            1
        );
        j3.append(&[Record::Drop { object: 10 }]).unwrap();
        assert_eq!(
            std::fs::read_to_string(p.join("index.jsonl"))
                .unwrap()
                .lines()
                .count(),
            2
        );
    }

    #[test]
    fn a_planted_link_or_foreign_dir_is_refused() {
        let t = tempfile::TempDir::new().unwrap();
        let target = t.path().join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        let link = t.path().join(".northnarrow-cow");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = format!("{:#}", Journal::open(&link).err().unwrap());
        assert!(err.contains("link"), "{err}");
        assert!(Journal::open(&t.path().join("no/such/.j")).is_err());
    }

    #[test]
    fn evidence_moves_by_rename() {
        let t = tempfile::TempDir::new().unwrap();
        let j = Journal::open(&t.path().join(".j")).unwrap();
        std::fs::write(t.path().join("a.locked"), b"junk").unwrap();
        let d = open_dir(t.path()).unwrap();
        let to = j.move_to_evidence(d.as_raw_fd(), "a.locked", 7).unwrap();
        assert!(to.ends_with("evidence/7-a.locked"), "{to}");
        assert!(!t.path().join("a.locked").exists());
        assert_eq!(
            std::fs::read(t.path().join(".j/evidence/7-a.locked")).unwrap(),
            b"junk"
        );
    }
}
