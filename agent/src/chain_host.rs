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

    /// [`Self::open_with_mode`] without following a final symlink.
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
