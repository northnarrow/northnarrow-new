//! The tests' chain host and key (nn-evidence keeps its own to itself).

use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use nn_evidence::chain_host::{ChainHost, ChainSigner};

/// Plain `std`, as nn-evidence's own tests' host.
pub(crate) struct TestHost;

impl ChainHost for TestHost {
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

#[derive(Debug)]
pub(crate) struct TestKey(pub SigningKey);

impl TestKey {
    pub(crate) fn new(seed: u8) -> Self {
        TestKey(SigningKey::from_bytes(&[seed; 32]))
    }
}

impl ChainSigner for TestKey {
    type Host = TestHost;
    fn sign(&self, msg: &[u8]) -> Signature {
        self.0.sign(msg)
    }
    fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
}
