//! The quarantine vault's records (Wave 4 restructure, R14c — plan §3.3):
//! the crypto of lab PRs 230 and 238, moved here from `response::quarantine`
//! as it was (the items made visible to the crate; their bodies unchanged).

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::response::config::ExecutorConfig;

/// The nonce of a record.
pub(crate) const NONCE_LEN: usize = 12;

/// HKDF salt of the v1 record (no header: the salt was the only version).
pub(crate) const KDF_SALT: &[u8] = b"northnarrow-quarantine-v1";
/// HKDF salt of the v2 record (lab PR 238).
pub(crate) const KDF_SALT_V2: &[u8] = b"northnarrow-quarantine-v2";
/// The first bytes of a record with a header (v2 and later).
pub(crate) const RECORD_MAGIC: [u8; 4] = *b"NNQV";
/// The format the quarantine writes (lab PR 238), the byte after
/// [`RECORD_MAGIC`] and the `.meta`'s `format`.
pub(crate) const RECORD_V2: u8 = 2;
/// [`RECORD_MAGIC`] and the version byte.
pub(crate) const HEADER_LEN: usize = RECORD_MAGIC.len() + 1;

/// Load the 32-byte master key. Generate + write mode 0600 on first
/// use.
pub(crate) fn load_or_init_master_key(
    cfg: &ExecutorConfig,
) -> std::io::Result<Zeroizing<[u8; 32]>> {
    if let Ok(bytes) = fs::read(&cfg.master_key_file) {
        if bytes.len() == 32 {
            let mut k = Zeroizing::new([0u8; 32]);
            k.copy_from_slice(&bytes);
            return Ok(k);
        }
        return Err(std::io::Error::other(format!(
            "master key at {} has wrong length {}",
            cfg.master_key_file.display(),
            bytes.len()
        )));
    }
    if let Some(parent) = cfg.master_key_file.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut k = Zeroizing::new([0u8; 32]);
    crate::os_rng::OsRng.fill_bytes(&mut *k);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&cfg.master_key_file)?;
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
