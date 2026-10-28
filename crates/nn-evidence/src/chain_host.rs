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
//!   (lab PR 241 moved the calls, not their arguments);
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
}
