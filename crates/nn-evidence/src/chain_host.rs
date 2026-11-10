//! What the signed chains need from the host that writes them (Wave 4
//! restructure, R04a, lab PR 241).
//!
//! The chain code — the canonical form, the writers, the verifiers — is
//! the same on every platform. Two things are not, and they are here as
//! traits the host implements (the agent: `LinuxHost` and
//! `AgentSigningKey`, in its `chain_host_linux` and `keys` modules):
//!
//! - [`ChainHost`]: the file operations portable `std` cannot spell — an
//!   open that does not follow a final symlink and does not block on a FIFO
//!   (`O_NOFOLLOW | O_NONBLOCK`), the mode of a file or directory a chain
//!   creates, a rename that never replaces (`renameat2(RENAME_NOREPLACE)`),
//!   a positioned write (`pwrite`), and the anchoring of a log's directory
//!   (review entry 44). Each is the call the chain code made itself before
//!   (lab PR 241 moved the calls, not their arguments). Lot 296: the append
//!   of a row and the `fsync` too, with `std`'s calls as their default — a
//!   test host fails them as a full disk or a failing device does;
//! - [`ChainSigner`]: the key the writers sign with, and the host its
//!   chains live on. No key material is kept by the chain code.
//!
//! The writers take the key (`AuditLog::open(path, key, agent_id)`), so they
//! find the host through it; a reader that takes no key names the host
//! (`boot_check::<H>`).

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, VerifyingKey};

/// The host's file operations the chains use.
pub trait ChainHost: 'static {
    /// Open `path` for reading without following a final symlink and
    /// without blocking on a FIFO.
    fn open_read_nofollow(path: &Path) -> io::Result<File>;

    /// `err` is how [`Self::open_read_nofollow`] refuses a final symlink.
    fn is_symlink_refusal(err: &io::Error) -> bool;

    /// Open with `options`; a file the open creates gets `mode`.
    fn open_with_mode(options: &mut OpenOptions, mode: u32, path: &Path) -> io::Result<File>;

    /// [`Self::open_with_mode`] without following a final symlink and
    /// without blocking on a FIFO (R11b, lab PR 262: the audit chain's
    /// opens, after review #466 F1).
    fn open_with_mode_nofollow(
        options: &mut OpenOptions,
        mode: u32,
        path: &Path,
    ) -> io::Result<File>;

    /// Create `dir` and its missing parents, each with `mode`.
    fn create_dir_all_with_mode(dir: &Path, mode: u32) -> io::Result<()>;

    /// `rename(from, to)` that fails with `AlreadyExists` instead of
    /// replacing `to`.
    fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()>;

    /// Write all of `buf` at `offset` of `file`.
    fn write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()>;

    /// `path` resolved through its directory as the host first saw it, so a
    /// later mount over the directory cannot divert a log's writes (review
    /// entry 44). Returned unchanged when the host does not anchor it.
    fn anchor(path: &Path) -> PathBuf;

    /// Write all of `buf` at the end of `file`, opened to append. Lot 296: a
    /// full disk stops it part-way (the first `write` takes what fits, the
    /// next fails): the writers re-read their tail before their next row.
    fn append_all(file: &mut File, buf: &[u8]) -> io::Result<()> {
        io::Write::write_all(file, buf)
    }

    /// `fsync` of `file`. Lot 296: it can fail after its row was written
    /// whole; the writers re-read their tail before their next row.
    fn sync_all(file: &File) -> io::Result<()> {
        file.sync_all()
    }
}

/// The key a chain writer signs with.
pub trait ChainSigner {
    /// The host the chains this key signs are written on.
    type Host: ChainHost;

    /// Sign `msg` (a chain line's 32-byte digest).
    fn sign(&self, msg: &[u8]) -> Signature;

    /// The public half, the verifiers' key.
    fn verifying_key(&self) -> VerifyingKey;
}

/// The chain code's own tests: a portable host and a key kept in a file.
/// What is Linux about the agent's host (modes, symlinks, FIFOs, the
/// anchor) is tested with it, in the agent.
#[cfg(test)]
pub(crate) mod testing {
    use std::fs::{File, OpenOptions};
    use std::io::{self, Seek, SeekFrom, Write};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
    use sha2::{Digest, Sha256};

    use super::{ChainHost, ChainSigner};

    /// Plain `std`: no mode, symlinks followed, no anchor; the rename
    /// checks the target first (the agent's fallback on a filesystem
    /// without `RENAME_NOREPLACE`).
    pub(crate) struct PortableHost;

    impl ChainHost for PortableHost {
        fn open_read_nofollow(path: &Path) -> io::Result<File> {
            OpenOptions::new().read(true).open(path)
        }
        fn is_symlink_refusal(_err: &io::Error) -> bool {
            false
        }
        fn open_with_mode(options: &mut OpenOptions, _mode: u32, path: &Path) -> io::Result<File> {
            options.open(path)
        }
        fn open_with_mode_nofollow(
            options: &mut OpenOptions,
            _mode: u32,
            path: &Path,
        ) -> io::Result<File> {
            options.open(path)
        }
        fn create_dir_all_with_mode(dir: &Path, _mode: u32) -> io::Result<()> {
            std::fs::create_dir_all(dir)
        }
        fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
            if std::fs::symlink_metadata(to).is_ok() {
                return Err(io::Error::from(io::ErrorKind::AlreadyExists));
            }
            std::fs::rename(from, to)
        }
        fn write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
            let mut f = file;
            f.seek(SeekFrom::Start(offset))?;
            f.write_all(buf)
        }
        fn anchor(path: &Path) -> PathBuf {
            path.to_path_buf()
        }
    }

    /// A test key, kept in a file by [`Self::load_or_bootstrap`].
    pub(crate) struct TestKey(SigningKey);

    impl std::fmt::Debug for TestKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "TestKey")
        }
    }

    impl TestKey {
        /// A key no other call returns.
        pub(crate) fn fresh() -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let mut h = Sha256::new();
            h.update(b"nn-evidence test key\0");
            h.update(N.fetch_add(1, Ordering::Relaxed).to_le_bytes());
            h.update(std::process::id().to_le_bytes());
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            h.update(nanos.to_le_bytes());
            TestKey(SigningKey::from_bytes(&h.finalize().into()))
        }

        /// The key in `path` (64 hex characters), written there first if the
        /// file is absent: the call shape of the agent's key, without its
        /// modes, so two loads of one path sign alike.
        pub(crate) fn load_or_bootstrap(path: &Path) -> anyhow::Result<Self> {
            if let Ok(text) = std::fs::read_to_string(path) {
                let bytes: [u8; 32] = hex::decode(text.trim())?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("{}: not 32 bytes", path.display()))?;
                return Ok(TestKey(SigningKey::from_bytes(&bytes)));
            }
            let key = Self::fresh();
            std::fs::write(path, format!("{}\n", hex::encode(key.0.to_bytes())))?;
            Ok(key)
        }
    }

    impl ChainSigner for TestKey {
        type Host = PortableHost;
        fn sign(&self, msg: &[u8]) -> Signature {
            self.0.sign(msg)
        }
        fn verifying_key(&self) -> VerifyingKey {
            self.0.verifying_key()
        }
    }

    /// Lot 296: a fault [`FaultyHost`] injects, once, into the next call it
    /// matches (the tests' threads each have their own).
    #[derive(Debug, Clone)]
    pub(crate) enum Fault {
        /// The next append of a row starting with `prefix` writes its first
        /// `keep` bytes to the file, then fails (`ENOSPC`): what a full disk
        /// leaves.
        ShortWrite { prefix: &'static [u8], keep: usize },
        /// The next append of a row starting with `prefix` is written whole,
        /// then its fsync fails (`EIO`).
        SyncFails { prefix: &'static [u8] },
        /// The next open of a path ending in `suffix` fails (`EIO`).
        OpenFails { suffix: &'static str },
        /// The next positioned write writes its first `keep` bytes, then
        /// fails (`ENOSPC`).
        ShortWriteAt { keep: usize },
    }

    thread_local! {
        static FAULTS: std::cell::RefCell<Vec<Fault>> = const { std::cell::RefCell::new(Vec::new()) };
        static SYNC_FAILS_NEXT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        static LEFT: std::cell::RefCell<Vec<Vec<u8>>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    /// Arm `fault` for this thread's next matching call.
    pub(crate) fn inject(fault: Fault) {
        FAULTS.with(|f| f.borrow_mut().push(fault));
    }

    /// The faults armed and not fired yet on this thread.
    pub(crate) fn armed() -> usize {
        FAULTS.with(|f| f.borrow().len())
    }

    /// What each short write fired on this thread left in its file, in
    /// order (taken).
    pub(crate) fn left_behind() -> Vec<Vec<u8>> {
        LEFT.with(|l| std::mem::take(&mut *l.borrow_mut()))
    }

    fn take_fault(matches: impl Fn(&Fault) -> bool) -> Option<Fault> {
        FAULTS.with(|f| {
            let mut f = f.borrow_mut();
            let i = f.iter().position(matches)?;
            Some(f.remove(i))
        })
    }

    fn open_fault(path: &Path) -> io::Result<()> {
        let p = path.to_string_lossy();
        match take_fault(|f| matches!(f, Fault::OpenFails { suffix } if p.ends_with(suffix))) {
            Some(_) => Err(io::Error::from_raw_os_error(5)),
            None => Ok(()),
        }
    }

    /// [`PortableHost`] with the [`Fault`]s armed on the thread.
    pub(crate) struct FaultyHost;

    impl ChainHost for FaultyHost {
        fn open_read_nofollow(path: &Path) -> io::Result<File> {
            open_fault(path)?;
            PortableHost::open_read_nofollow(path)
        }
        fn is_symlink_refusal(err: &io::Error) -> bool {
            PortableHost::is_symlink_refusal(err)
        }
        fn open_with_mode(options: &mut OpenOptions, mode: u32, path: &Path) -> io::Result<File> {
            open_fault(path)?;
            PortableHost::open_with_mode(options, mode, path)
        }
        fn open_with_mode_nofollow(
            options: &mut OpenOptions,
            mode: u32,
            path: &Path,
        ) -> io::Result<File> {
            open_fault(path)?;
            PortableHost::open_with_mode_nofollow(options, mode, path)
        }
        fn create_dir_all_with_mode(dir: &Path, mode: u32) -> io::Result<()> {
            PortableHost::create_dir_all_with_mode(dir, mode)
        }
        fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
            PortableHost::rename_noreplace(from, to)
        }
        fn write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
            if let Some(Fault::ShortWriteAt { keep }) =
                take_fault(|f| matches!(f, Fault::ShortWriteAt { .. }))
            {
                let keep = keep.min(buf.len());
                PortableHost::write_all_at(file, &buf[..keep], offset)?;
                LEFT.with(|l| l.borrow_mut().push(buf[..keep].to_vec()));
                return Err(io::Error::from_raw_os_error(28));
            }
            PortableHost::write_all_at(file, buf, offset)
        }
        fn anchor(path: &Path) -> PathBuf {
            PortableHost::anchor(path)
        }
        fn append_all(file: &mut File, buf: &[u8]) -> io::Result<()> {
            match take_fault(|f| match f {
                Fault::ShortWrite { prefix, .. } | Fault::SyncFails { prefix } => {
                    buf.starts_with(prefix)
                }
                _ => false,
            }) {
                Some(Fault::ShortWrite { keep, .. }) => {
                    let keep = keep.min(buf.len());
                    file.write_all(&buf[..keep])?;
                    LEFT.with(|l| l.borrow_mut().push(buf[..keep].to_vec()));
                    Err(io::Error::from_raw_os_error(28))
                }
                Some(_) => {
                    file.write_all(buf)?;
                    SYNC_FAILS_NEXT.with(|s| s.set(true));
                    Ok(())
                }
                None => file.write_all(buf),
            }
        }
        fn sync_all(file: &File) -> io::Result<()> {
            if SYNC_FAILS_NEXT.with(|s| s.replace(false)) {
                return Err(io::Error::from_raw_os_error(5));
            }
            file.sync_all()
        }
    }

    /// A [`TestKey`] whose chains live on the [`FaultyHost`].
    pub(crate) struct FaultyKey(pub(crate) TestKey);

    impl ChainSigner for FaultyKey {
        type Host = FaultyHost;
        fn sign(&self, msg: &[u8]) -> Signature {
            self.0.sign(msg)
        }
        fn verifying_key(&self) -> VerifyingKey {
            self.0.verifying_key()
        }
    }
}
