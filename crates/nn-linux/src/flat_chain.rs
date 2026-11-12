//! The flat chains' writer after a failed write (lot 319; lot 296's
//! backlog: its poisoned-writer scheme, on the chains it left).
//!
//! The canary registry and access log, the FIM baseline and the listener
//! log are flat chains: one file, never rotated, each row chained to the one
//! before, appended through `O_APPEND`. Lot 296 gave the audit log and the
//! rotating chains a writer that knows a failed write left the file in a
//! state it does not know; these four wrote with `write_all` and went on
//! after an error as if nothing had reached the file:
//!
//! - a full disk stops a write part-way (the first `write` takes what fits,
//!   the next fails): the start of the row stayed, and the next row was
//!   glued to it — one line no row. The registry and the access log skipped
//!   it at the next start (their chains break there: the row after it names
//!   a row no longer read); the listener log no longer opened (its reader is
//!   strict: the drain wrote no listener that boot);
//! - an fsync that fails after a whole row: the next row chained off the row
//!   before it — a fork.
//!
//! [`FlatFile`] is the one writer of their rows. A failed append or fsync
//! poisons it; before the next row the chain reads its tail again
//! ([`FlatFile::heal`]): what the failure left after the last newline is cut
//! ([`crate::chainlog::repair_torn_tail`], as the open does), and the chain
//! takes its tail from the file — a row written whole is its tail. The cut
//! is signed in the audit chain (`chain_tail_repaired`, the fragment's
//! length and SHA-256) like the open's repairs, by
//! [`crate::boot::degradation::attest_repair`]: at once when the audit log
//! is free, else at its next flush. As at the open, the cut comes first and
//! its record after it (a flat chain has no manifest of its own to attest
//! in before the cut).
//!
//! The repository's test `xtask/tests/flat_chain_writes.rs` keeps every
//! flat chain's append here.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::warn;

/// The append side of one flat chain file.
#[derive(Debug)]
pub struct FlatFile {
    /// Where the rows are appended: through the directory fd the open took
    /// (review entry 44, [`crate::anchored::anchor`]).
    path: PathBuf,
    /// The file as the agent's command line names it: what the
    /// attestations say.
    name: PathBuf,
    mode: u32,
    /// An append or an fsync failed (the error): what it left in the file
    /// is not known.
    poisoned: Option<String>,
    #[cfg(test)]
    fail_next_sync: bool,
    /// Tests: the next append writes its line but its last `n` bytes, then
    /// fails (`ENOSPC`) — a full disk's short write.
    #[cfg(test)]
    cut_next_write: Option<usize>,
}

impl FlatFile {
    /// The chain file at `path`, created with `mode` by its first row.
    pub fn new(path: &Path, mode: u32) -> Self {
        Self {
            path: crate::anchored::anchor(path),
            name: path.to_path_buf(),
            mode,
            poisoned: None,
            #[cfg(test)]
            fail_next_sync: false,
            #[cfg(test)]
            cut_next_write: None,
        }
    }

    /// The path the rows are appended through.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A failed append or fsync waits for [`Self::heal`].
    pub fn poisoned(&self) -> bool {
        self.poisoned.is_some()
    }

    /// Append `line` (one row with its newline) at the end of the file, and
    /// `fsync` it when `sync`. A failure poisons the file: the next row
    /// [`Self::heal`]s it first.
    pub fn append(&mut self, line: &[u8], sync: bool) -> Result<()> {
        let r = self.append_inner(line, sync);
        if let Err(e) = &r {
            self.poisoned = Some(format!("{e:#}"));
        }
        r
    }

    fn append_inner(&mut self, line: &[u8], sync: bool) -> Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(self.mode)
            .open(&self.path)
            .with_context(|| format!("opening {} for append", self.name.display()))?;
        #[cfg(test)]
        if let Some(n) = self.cut_next_write.take() {
            f.write_all(&line[..line.len().saturating_sub(n)])?;
            return Err(anyhow::anyhow!(std::io::Error::from_raw_os_error(
                libc::ENOSPC
            )))
            .with_context(|| format!("appending a row to {}", self.name.display()));
        }
        f.write_all(line)
            .with_context(|| format!("appending a row to {}", self.name.display()))?;
        if sync {
            self.sync_file(&f)?;
        }
        Ok(())
    }

    /// `fsync` of the rows appended without (the listener log's group
    /// commit). A failure poisons the file.
    pub fn sync(&mut self) -> Result<()> {
        let r = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .with_context(|| format!("opening {} for fsync", self.name.display()))
            .and_then(|f| self.sync_file(&f));
        if let Err(e) = &r {
            self.poisoned = Some(format!("{e:#}"));
        }
        r
    }

    fn sync_file(&mut self, f: &std::fs::File) -> Result<()> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_sync) {
            return Err(anyhow::anyhow!(std::io::Error::from_raw_os_error(
                libc::EIO
            )))
            .with_context(|| format!("fsync {}", self.name.display()));
        }
        f.sync_all()
            .with_context(|| format!("fsync {}", self.name.display()))
    }

    /// Before a row, after a failed append or fsync (nothing when the file
    /// is not poisoned: `Ok(None)`). What the failure left after the last
    /// newline is cut — a fragment `is_row` does not take — or closed (a
    /// whole row whose newline did not reach the disk), and the change
    /// signed in the audit chain; then `reread` reads the chain's tail from
    /// the file, which the caller takes (a row the failure wrote whole is
    /// the tail now). On an error the file stays poisoned and nothing may be
    /// written: the next row tries again.
    pub fn heal<T>(
        &mut self,
        is_row: impl Fn(&[u8]) -> bool,
        reread: impl FnOnce(&Path) -> Result<T>,
    ) -> Result<Option<T>> {
        let Some(cause) = self.poisoned.as_deref() else {
            return Ok(None);
        };
        warn!(
            file = %self.name.display(),
            cause,
            "flat chain: a write failed; reading the file's tail again before the next row"
        );
        let repair = crate::chainlog::repair_torn_tail::<crate::chain_host_linux::LinuxHost>(
            &self.path, is_row,
        )
        .with_context(|| {
            format!(
                "{}: reading its tail again after a failed write",
                self.name.display()
            )
        })?;
        if let Some(r) = repair {
            crate::boot::degradation::attest_repair(&self.name, r);
        }
        let tail = reread(&self.path).with_context(|| {
            format!(
                "{}: reading its tail again after a failed write",
                self.name.display()
            )
        })?;
        self.poisoned = None;
        Ok(Some(tail))
    }

    /// Tests: the next fsync fails (`EIO`) after its row was written whole.
    #[cfg(test)]
    pub fn fail_next_sync(&mut self) {
        self.fail_next_sync = true;
    }

    /// Tests: the next append writes its line but its last `n` bytes, then
    /// fails (`ENOSPC`).
    #[cfg(test)]
    pub fn cut_next_write(&mut self, n: usize) {
        self.cut_next_write = Some(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_row(l: &[u8]) -> bool {
        serde_json::from_slice::<serde_json::Value>(l).is_ok()
    }

    fn reread(p: &Path) -> Result<Vec<String>> {
        Ok(std::fs::read_to_string(p)?
            .lines()
            .map(str::to_string)
            .collect())
    }

    /// A row written whole whose fsync failed poisons the file; the heal
    /// cuts nothing (no fragment) and the reread sees that row.
    #[test]
    fn a_failed_fsync_poisons_and_the_heal_keeps_the_whole_row() {
        // the repairs go to the process's registry: one test at a time
        let _g = crate::boot::degradation::TEST_LOCK.lock();
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("chain.jsonl");
        let mut f = FlatFile::new(&p, 0o600);
        assert!(f.heal(is_row, reread).unwrap().is_none(), "not poisoned");
        f.append(b"{\"n\":1}\n", true).unwrap();
        f.fail_next_sync();
        assert!(f.append(b"{\"n\":2}\n", true).is_err());
        assert!(f.poisoned());
        let tail = f.heal(is_row, reread).unwrap().expect("healed");
        assert_eq!(tail, ["{\"n\":1}", "{\"n\":2}"]);
        assert!(!f.poisoned());
        assert!(f.heal(is_row, reread).unwrap().is_none(), "once");
    }

    /// A fragment left at the end is cut before the reread; a reread that
    /// fails leaves the file poisoned (the next row tries again).
    #[test]
    fn the_heal_cuts_a_fragment_and_a_failed_reread_stays_poisoned() {
        // the repairs go to the process's registry: one test at a time
        let _g = crate::boot::degradation::TEST_LOCK.lock();
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("chain.jsonl");
        let mut f = FlatFile::new(&p, 0o600);
        f.append(b"{\"n\":1}\n", true).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&p)
            .unwrap()
            .write_all(b"{\"n\":")
            .unwrap();
        f.poisoned = Some("a short write".into());
        let e = f
            .heal(is_row, |_| -> Result<()> { anyhow::bail!("unreadable") })
            .unwrap_err();
        assert!(format!("{e:#}").contains("unreadable"));
        assert!(f.poisoned(), "still poisoned");
        assert_eq!(
            std::fs::read(&p).unwrap(),
            b"{\"n\":1}\n",
            "the cut is done"
        );
        let tail = f.heal(is_row, reread).unwrap().unwrap();
        assert_eq!(tail, ["{\"n\":1}"]);
        assert!(!f.poisoned());
        crate::boot::degradation::reset_for_tests();
    }

    /// The rows go through the anchor, the attestation names the file.
    #[test]
    fn the_rows_go_through_the_anchor() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("chain.jsonl");
        let f = FlatFile::new(&p, 0o600);
        assert!(
            f.path().starts_with("/proc/self/fd"),
            "{}",
            f.path().display()
        );
        assert_eq!(f.name, p);
    }
}
