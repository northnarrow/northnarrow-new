//! The quarantine vault's key and its records (Wave 4 restructure, R14c —
//! plan §3.3; the crypto lab PR 230 and 238 wrote, moved here from
//! `response::quarantine` unchanged).
//!
//! [`Vault`] is the [`super::KeyStore`]'s handle on the master key: 32
//! random bytes at the configured path (`/etc/northnarrow/master.key`,
//! 0600), created at the first use as before, read once, then held in
//! memory of its own ([`super::locked::Locked`]: `mlock`, `MADV_DONTDUMP`,
//! zeroed when dropped). The quarantine seals and opens records through it
//! (`nn_core::response::config::VaultKey`) and never holds the key; a
//! configuration without the store's vault (the tests') gets one for its
//! path.
//!
//! The records:
//! - **v2**, written since lab PR 238: `"NNQV" ‖ 0x02 ‖ nonce (12) ‖
//!   ciphertext ‖ tag (16)`, AES-256-GCM under HKDF-SHA256 of the master
//!   key, salt `"northnarrow-quarantine-v2"`, info the vault id; the header
//!   and the vault id authenticated with it;
//! - **v1**, written before: `nonce (12) ‖ ciphertext ‖ tag (16)`, salt
//!   `"northnarrow-quarantine-v1"`, the vault id as associated data. Read,
//!   never written.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::locked::Locked;

/// The nonce of a record.
pub const NONCE_LEN: usize = 12;

/// HKDF salt of the v1 record (no header: the salt was the only version).
pub(crate) const KDF_SALT: &[u8] = b"northnarrow-quarantine-v1";
/// HKDF salt of the v2 record (lab PR 238).
pub(crate) const KDF_SALT_V2: &[u8] = b"northnarrow-quarantine-v2";
/// The first bytes of a record with a header (v2 and later).
pub(crate) const RECORD_MAGIC: [u8; 4] = *b"NNQV";
/// The format the quarantine writes (lab PR 238), the byte after
/// [`RECORD_MAGIC`] and the `.meta`'s `format`.
pub const RECORD_V2: u8 = 2;
/// [`RECORD_MAGIC`] and the version byte.
pub(crate) const HEADER_LEN: usize = RECORD_MAGIC.len() + 1;

/// The vault's master key, held once ([`super::KeyStore::vault`]); a
/// clone shares it.
#[derive(Clone)]
pub struct Vault(Arc<Inner>);

/// The master key in its locked mapping, shared by the vault's clones.
type MasterKey = Arc<Locked<Zeroizing<[u8; 32]>>>;

struct Inner {
    path: PathBuf,
    key: parking_lot::Mutex<Option<MasterKey>>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.0.path)
            .field("loaded", &self.0.key.lock().is_some())
            .finish()
    }
}

impl Vault {
    /// The vault whose master key is at `path` (nothing read yet).
    pub fn at(path: &Path) -> Self {
        Self(Arc::new(Inner {
            path: path.to_path_buf(),
            key: parking_lot::Mutex::new(None),
        }))
    }

    pub fn path(&self) -> &Path {
        &self.0.path
    }

    /// The master key: read (or created) at the first use, then held.
    fn master(&self) -> std::io::Result<Arc<Locked<Zeroizing<[u8; 32]>>>> {
        let mut slot = self.0.key.lock();
        if let Some(k) = slot.as_ref() {
            return Ok(Arc::clone(k));
        }
        let k = Arc::new(Locked::new(load_or_init_master_key(&self.0.path)?)?);
        // review of #482 (R14c-3): as the signing key's — signed when the
        // memory is not locked or not out of the dumps
        super::report_memory("the vault's master key", k.locked(), k.dontdump());
        *slot = Some(Arc::clone(&k));
        Ok(k)
    }

    /// A v2 record of `content` for the entry `vault_id`.
    pub fn seal_v2(
        &self,
        vault_id: &str,
        nonce: &[u8; NONCE_LEN],
        content: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        let master = self.master()?;
        seal_v2(&master, vault_id, nonce, content)
            .map_err(|e| std::io::Error::other(format!("encrypt: {e}")))
    }

    /// The content of a record in the format its first bytes name.
    pub fn open(&self, vault_id: &str, bin: &[u8]) -> std::io::Result<Zeroizing<Vec<u8>>> {
        let master = self.master()?;
        open(&master, vault_id, bin)
    }

    /// A v1 record's content (an entry whose `.meta` names no format).
    pub fn open_v1(&self, vault_id: &str, bin: &[u8]) -> std::io::Result<Zeroizing<Vec<u8>>> {
        let master = self.master()?;
        open_v1(&master, vault_id, bin)
    }

    /// R14c: the key is held, locked in RAM and out of the core dumps
    /// (`None`: not used yet).
    pub fn protected(&self) -> Option<(bool, bool)> {
        self.0
            .key
            .lock()
            .as_ref()
            .map(|k| (k.locked(), k.dontdump()))
    }
}

/// A vault for the master key at `path`, for the tests' configurations
/// without the key store's (`vault_of` in the quarantine); no build of the
/// binaries has it.
#[cfg(any(test, feature = "test-util"))]
pub fn for_tests(path: &Path) -> Vault {
    Vault::at(path)
}

impl nn_core::response::config::VaultKey for Vault {
    fn seal(&self, vault_id: &str, nonce: &[u8; 12], content: &[u8]) -> std::io::Result<Vec<u8>> {
        self.seal_v2(vault_id, nonce, content)
    }
    fn open(&self, vault_id: &str, record: &[u8]) -> std::io::Result<Vec<u8>> {
        Vault::open(self, vault_id, record).map(|z| z.to_vec())
    }
    fn open_v1(&self, vault_id: &str, record: &[u8]) -> std::io::Result<Vec<u8>> {
        Vault::open_v1(self, vault_id, record).map(|z| z.to_vec())
    }
}

/// Load the 32-byte master key at `path`. Generate + write mode 0600 on
/// first use (the quarantine's `load_or_init_master_key` until R14c).
///
/// Review of #482 (R14c-7): read as the signing key is
/// (`super::read_key_bytes`: a regular file, never a wait on a FIFO, at
/// most 4 KiB, zeroed); an absent file is created; anything else at the
/// name is an error, never replaced.
pub(crate) fn load_or_init_master_key(path: &Path) -> std::io::Result<Zeroizing<[u8; 32]>> {
    match super::read_key_bytes(path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut k = Zeroizing::new([0u8; 32]);
            k.copy_from_slice(&bytes);
            return Ok(k);
        }
        Ok(bytes) => {
            return Err(std::io::Error::other(format!(
                "master key at {} has wrong length {}",
                path.display(),
                bytes.len()
            )))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(std::io::Error::new(
                e.kind(),
                format!("master key at {}: {e}", path.display()),
            ))
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut k = Zeroizing::new([0u8; 32]);
    crate::os_rng::OsRng.fill_bytes(&mut *k);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(&*k)?;
    f.sync_all()?;
    Ok(k)
}

/// The per-entry key of a v1 record: HKDF-SHA256 of the master key, salt
/// [`KDF_SALT`], info the vault id. Lab PR 230 pins it.
pub(crate) fn derive_file_key(master: &Zeroizing<[u8; 32]>, vault_id: &str) -> Zeroizing<[u8; 32]> {
    derive_key(KDF_SALT, master, vault_id)
}

/// The per-entry key of a v2 record (lab PR 238): as [`derive_file_key`]
/// with the salt [`KDF_SALT_V2`].
pub(crate) fn derive_file_key_v2(
    master: &Zeroizing<[u8; 32]>,
    vault_id: &str,
) -> Zeroizing<[u8; 32]> {
    derive_key(KDF_SALT_V2, master, vault_id)
}

pub(crate) fn derive_key(
    salt: &[u8],
    master: &Zeroizing<[u8; 32]>,
    vault_id: &str,
) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), &**master);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(vault_id.as_bytes(), &mut *out)
        .expect("HKDF 32-byte expand cannot fail");
    out
}

/// The v2 header: [`RECORD_MAGIC`] and [`RECORD_V2`].
pub(crate) fn header_v2() -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..RECORD_MAGIC.len()].copy_from_slice(&RECORD_MAGIC);
    h[RECORD_MAGIC.len()] = RECORD_V2;
    h
}

/// The associated data of a v2 record: its header, then the vault id.
pub(crate) fn aad_v2(vault_id: &str) -> Vec<u8> {
    let mut aad = header_v2().to_vec();
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}

/// AES-256-GCM of `content` for the vault entry `vault_id` in the v1
/// format, under its [`derive_file_key`] with the vault id as associated
/// data: ciphertext ‖ tag (16 bytes), the `.bin` of a v1 entry being
/// `nonce (12) ‖` this. Nothing writes v1 any more (lab PR 238): kept for
/// the vectors of lab PR 230, which pin what entries written before hold.
#[cfg(test)]
pub(crate) fn seal(
    master: &Zeroizing<[u8; 32]>,
    vault_id: &str,
    nonce: &[u8; NONCE_LEN],
    content: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let key = derive_file_key(master, vault_id);
    let cipher = Aes256Gcm::new((&*key).into());
    cipher.encrypt(
        &Nonce::from(*nonce),
        Payload {
            msg: content,
            aad: vault_id.as_bytes(),
        },
    )
}

/// The `.bin` of the vault entry `vault_id` in the v2 format (lab PR 238):
/// `"NNQV" ‖ 0x02 ‖ nonce (12) ‖ ciphertext ‖ tag (16)`, AES-256-GCM under
/// its [`derive_file_key_v2`] with the header and the vault id as
/// associated data. [`open`] reads it back.
pub(crate) fn seal_v2(
    master: &Zeroizing<[u8; 32]>,
    vault_id: &str,
    nonce: &[u8; NONCE_LEN],
    content: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let key = derive_file_key_v2(master, vault_id);
    let cipher = Aes256Gcm::new((&*key).into());
    let sealed = cipher.encrypt(
        &Nonce::from(*nonce),
        Payload {
            msg: content,
            aad: &aad_v2(vault_id),
        },
    )?;
    let mut record = Vec::with_capacity(HEADER_LEN + NONCE_LEN + sealed.len());
    record.extend_from_slice(&header_v2());
    record.extend_from_slice(nonce);
    record.extend_from_slice(&sealed);
    Ok(record)
}

pub(crate) fn bad_record(msg: String) -> std::io::Error {
    std::io::Error::new(ErrorKind::InvalidData, msg)
}

/// The format of a `.bin` by its first bytes: 1 for a record without a
/// header (v1), else the version byte after [`RECORD_MAGIC`]. A header cut
/// before its version byte, or one naming 0 or 1 (formats without a
/// header), is refused.
pub(crate) fn record_format(bin: &[u8]) -> std::io::Result<u8> {
    let Some(rest) = bin.strip_prefix(&RECORD_MAGIC) else {
        return Ok(1);
    };
    match rest.first() {
        Some(&v) if v >= RECORD_V2 => Ok(v),
        Some(&v) => Err(bad_record(format!(
            "vault record header names format {v}, which has no header — refused"
        ))),
        None => Err(bad_record(
            "vault record header cut before its version byte — refused".into(),
        )),
    }
}

/// The content of the `.bin` of the vault entry `vault_id`, in the format
/// its first bytes name ([`record_format`]): v2 ([`seal_v2`]) or v1 (no
/// header). A record of a format this agent does not read is refused, as
/// is one whose tag, nonce, header or vault id do not match.
pub(crate) fn open(
    master: &Zeroizing<[u8; 32]>,
    vault_id: &str,
    bin: &[u8],
) -> std::io::Result<Zeroizing<Vec<u8>>> {
    match record_format(bin)? {
        1 => open_v1(master, vault_id, bin),
        RECORD_V2 => open_v2(master, vault_id, bin),
        v => Err(bad_record(format!(
            "vault record format {v} is not one this agent reads (1, {RECORD_V2}) — refused"
        ))),
    }
}

/// A v1 record: `nonce ‖ ciphertext ‖ tag`, refused when its tag, its
/// nonce or its vault id do not match.
pub(crate) fn open_v1(
    master: &Zeroizing<[u8; 32]>,
    vault_id: &str,
    bin: &[u8],
) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let (nonce, ciphertext) = bin
        .split_at_checked(NONCE_LEN)
        .ok_or_else(|| std::io::Error::other("vault file too short"))?;
    let nonce: &[u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| std::io::Error::other("vault nonce is not 12 bytes"))?;
    let key = derive_file_key(master, vault_id);
    let cipher = Aes256Gcm::new((&*key).into());
    let plaintext = cipher
        .decrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad: vault_id.as_bytes(),
            },
        )
        .map_err(|e| std::io::Error::other(format!("decrypt: {e}")))?;
    Ok(Zeroizing::new(plaintext))
}

/// A v2 record ([`seal_v2`]), refused when its header is not v2's or its
/// tag, nonce or vault id do not match.
pub(crate) fn open_v2(
    master: &Zeroizing<[u8; 32]>,
    vault_id: &str,
    bin: &[u8],
) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let (header, rest) = bin
        .split_at_checked(HEADER_LEN)
        .ok_or_else(|| bad_record("vault record header cut — refused".into()))?;
    if header != header_v2() {
        return Err(bad_record("not a v2 vault record header — refused".into()));
    }
    let (nonce, ciphertext) = rest
        .split_at_checked(NONCE_LEN)
        .ok_or_else(|| std::io::Error::other("vault file too short"))?;
    let nonce: &[u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| std::io::Error::other("vault nonce is not 12 bytes"))?;
    let key = derive_file_key_v2(master, vault_id);
    let cipher = Aes256Gcm::new((&*key).into());
    let plaintext = cipher
        .decrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad: &aad_v2(vault_id),
            },
        )
        .map_err(|e| std::io::Error::other(format!("decrypt: {e}")))?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R14c: the master key is read once, at the vault's first use, and
    /// held: a record sealed then still opens after the file is gone (a
    /// vault that read the file again would make a new key and refuse it),
    /// and the key is locked and out of the dumps when the kernel lets it.
    #[test]
    fn the_master_key_is_read_once_and_held() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.key");
        let vault = Vault::at(&path);
        assert_eq!(vault.protected(), None, "nothing read before the first use");
        let record = vault.seal_v2("q-1", &[7u8; NONCE_LEN], b"payload").unwrap();
        assert!(path.exists(), "the key made at the first use");
        let (_, dontdump) = vault.protected().expect("held");
        assert!(dontdump);
        fs::remove_file(&path).unwrap();
        assert_eq!(&*vault.open("q-1", &record).unwrap(), b"payload");
        // a clone shares the key it holds
        let twin = vault.clone();
        assert_eq!(&*twin.open("q-1", &record).unwrap(), b"payload");
        assert!(!path.exists(), "not read, not made again");
        // another vault on the same path reads the file it finds: a new key
        let other = Vault::at(&path);
        assert!(other.open("q-1", &record).is_err());
    }
}
