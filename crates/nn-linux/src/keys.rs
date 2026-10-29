//! The agent's signing key: the Ed25519 key that signs every chain it
//! writes, on disk (`/etc/northnarrow/agent.sig.key`, 0400) and its public
//! half next to it (`agent.sig.pub`, 0444).
//!
//! Wave 4 restructure, R04a (lab PR 241): from `crate::audit`, unchanged
//! (plan R04a: "AgentSigningKey si separa dal formato"; it becomes nn-linux's
//! `keys` in R09a). The chain code signs through
//! [`crate::chain_host::ChainSigner`] and holds no key material of its own;
//! `crate::audit` re-exports these names until the shims go (R17).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use rand::rngs::SysRng;
use rand::TryRng;
use tracing::{info, warn};

use crate::audit::PARENT_DIR_MODE;
use crate::chain_host::ChainSigner;

/// Default location of the agent's audit-log signing key. Stored
/// as exactly 32 lowercase-hex bytes + `\n` so an operator can
/// inspect it with `cat` (cf. the agent_id encoding) without the
/// risk of a base64 padding mismatch.
pub const DEFAULT_SIGNING_KEY_PATH: &str = "/etc/northnarrow/agent.sig.key";

/// Owner-read-only — only the boot user (root) loads or rotates
/// it. The file is the LSM-protected signing-key root-of-trust;
/// `0400` keeps a curious non-root admin tool from accidentally
/// reading it before the LSM widening lands.
const SIGNING_KEY_FILE_MODE: u32 = 0o400;

/// Strict pre-decode length check: an Ed25519 secret key is
/// exactly 32 bytes ⇒ exactly 64 hex chars on disk.
const SIGNING_KEY_HEX_LEN: usize = SECRET_KEY_LENGTH * 2;

/// Agent-owned Ed25519 keypair that signs audit-log entries. The
/// key is **internal** to the agent install — not an admin key,
/// not user-facing — and is rotated only by re-installing the
/// agent with its identity retired (lab PR 265: `uninstall.sh
/// --purge`, then a fresh install; an absent key is never minted where
/// an earlier identity is on record). Off-host verifiers consume the pubkey via
/// [`AgentSigningKey::verifying_key`] which the future
/// `nn-admin audit verify` command will accept on the CLI.
///
/// Wrapping `SigningKey` (not transparent newtype) so the
/// secret bytes never accidentally leak through `Debug` or
/// `Display` derives. `Drop` zeroisation is owned by
/// `ed25519-dalek`'s `zeroize` feature in its standard build.
pub struct AgentSigningKey {
    inner: SigningKey,
}

// Manual Debug: never print the secret bytes. We expose the
// public verifying key's fingerprint instead so logs + test
// failure output stay informative without leaking secrets.
impl std::fmt::Debug for AgentSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pk = self.inner.verifying_key().to_bytes();
        write!(f, "AgentSigningKey(pubkey_fp={})", hex::encode(&pk[..4]))
    }
}

impl AgentSigningKey {
    /// Open `path` if it exists, else mint a fresh keypair via
    /// `OsRng` and persist it atomically. Returns the loaded /
    /// minted key.
    ///
    /// Errors are the same shape as
    /// [`crate::agent_id::load_or_bootstrap`]:
    /// - corrupted file (wrong length, non-hex) → hard error,
    ///   operator must investigate. Silent regeneration is
    ///   forbidden because a new key would silently invalidate
    ///   every signature in the existing audit log.
    /// - I/O refused (`EROFS`, `ENOSPC`, missing parent we
    ///   can't create) → propagated with context.
    ///
    /// R11b (lab PR 262, review #466 F4): the file must be a regular one,
    /// read to a bound ([`read_key_file`]) — a bind mount of `/dev/null`, a
    /// device or a FIFO over the name is an error (the start refuses), not
    /// an empty key —, and no error quotes its content.
    ///
    /// Lab PR 265 (review #466 F4-bis): an absent key whose public half is
    /// beside its name (`agent.sig.pub`) is not minted either: it was
    /// removed or is hidden, and a new key would publish its own half over
    /// the old one and restart every chain under another identity. The
    /// start's `boot::checks::signing_identity` refuses it before any load
    /// (on the rest of the evidence too: the install's id, signed rows);
    /// this keeps every other caller from minting one.
    pub fn load_or_bootstrap(path: &Path) -> Result<Self> {
        match read_key_file(path) {
            Ok(content) => {
                let key = parse_signing_key(&content).with_context(|| {
                    format!(
                        "agent signing key {} present but corrupted — refuse to \
                         silently regenerate; to re-key on purpose, retire the \
                         install's identity (docs/operator/INSTALL_UPGRADE_UNINSTALL.md, \
                         \"Re-keying the agent\"): removing the file alone refuses \
                         the start",
                        path.display()
                    )
                })?;
                info!(
                    target: "audit.signing_key",
                    path = %path.display(),
                    "reusing existing agent signing key"
                );
                let key = Self { inner: key };
                key.publish_verifying_key(path);
                Ok(key)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let public = verifying_key_path(path);
                if fs::symlink_metadata(&public).is_ok() {
                    return Err(anyhow!(
                        "agent signing key {} is absent but its public half {} is there: the key \
                         was removed or is hidden (a mount over its directory?) — refusing to mint \
                         a new one, which would restart every chain under another identity",
                        path.display(),
                        public.display()
                    ));
                }
                let key = mint_signing_key()?;
                persist_signing_key_atomically(path, &key)?;
                info!(
                    target: "audit.signing_key",
                    path = %path.display(),
                    "bootstrapped fresh agent signing key"
                );
                let key = Self { inner: key };
                key.publish_verifying_key(path);
                Ok(key)
            }
            Err(e) => Err(anyhow!(e).context(format!("reading {}", path.display()))),
        }
    }

    /// Public verifying key for off-host auditors. Embeds in the
    /// agent binary at build time so `nn-admin audit verify`
    /// doesn't need a separate key distribution step.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.inner.verifying_key()
    }

    /// External audit EVD-001: write the public half next to the key
    /// (`agent.sig.key` → `agent.sig.pub`, 64 hex chars, mode 0444) unless
    /// it already says the same. The private key is closed to every reader
    /// outside the agent's family, root included; `nn-admin audit verify`
    /// and any auditor read this instead. Best effort: a failure is logged.
    pub fn publish_verifying_key(&self, key_path: &Path) {
        let pub_path = verifying_key_path(key_path);
        let want = format!("{}\n", hex::encode(self.verifying_key().to_bytes()));
        if fs::read_to_string(&pub_path).is_ok_and(|have| have == want) {
            return;
        }
        let tmp = pub_path.with_extension("pub.tmp");
        let written = (|| -> std::io::Result<()> {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let _ = fs::remove_file(&tmp);
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o444)
                .open(&tmp)?;
            f.write_all(want.as_bytes())?;
            f.sync_all()?;
            fs::rename(&tmp, &pub_path)
        })();
        match written {
            Ok(()) => info!(
                target: "audit.signing_key",
                path = %pub_path.display(),
                "agent signing key's public half published"
            ),
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                warn!(
                    target: "audit.signing_key",
                    path = %pub_path.display(),
                    error = %e,
                    "could not publish the agent signing key's public half"
                );
            }
        }
    }

    /// Sign `msg` with the agent signing key. Used by
    /// [`AuditLog::append`] to sign `entry_hash`; exposed for
    /// tests + the future `audit verify` reader.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.inner.sign(msg)
    }
}

fn mint_signing_key() -> Result<SigningKey> {
    let mut secret = [0u8; SECRET_KEY_LENGTH];
    SysRng.try_fill_bytes(&mut secret).map_err(|e| {
        anyhow!("the OS random source failed to provide entropy for signing key: {e}")
    })?;
    Ok(SigningKey::from_bytes(&secret))
}

/// External audit EVD-001: where the public half of the signing key at
/// `key_path` lives (`agent.sig.key` → `agent.sig.pub`).
pub fn verifying_key_path(key_path: &Path) -> std::path::PathBuf {
    key_path.with_extension("pub")
}

/// The verifying key `publish_verifying_key` wrote at `path`.
pub fn read_verifying_key(path: &Path) -> Result<VerifyingKey> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let bytes = hex::decode(raw.trim()).map_err(|e| anyhow!("{}: not hex: {e}", path.display()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("{}: not 32 bytes", path.display()))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| anyhow!("{}: not an Ed25519 key: {e}", path.display()))
}

/// The private key at `path`, read and parsed — never minted (legacy
/// verification on a host without `agent.sig.pub`).
pub fn read_signing_key(path: &Path) -> Result<AgentSigningKey> {
    let raw = read_key_file(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(AgentSigningKey {
        inner: parse_signing_key(&raw)?,
    })
}

/// The longest key file read: the key is 64 hex characters and a newline.
const MAX_KEY_FILE_BYTES: u64 = 4096;

/// R11b (lab PR 262, review #466 F4): the text of the key file at `path`,
/// without waiting on a FIFO: a regular file, at most
/// [`MAX_KEY_FILE_BYTES`], UTF-8. Anything else at the name — a character
/// device (a bind mount of `/dev/null`), a FIFO, a socket, a directory — is
/// an `InvalidData` error naming what it is.
fn read_key_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    use std::os::unix::fs::FileTypeExt;
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    let t = f.metadata()?.file_type();
    if !t.is_file() {
        let what = if t.is_char_device() || t.is_block_device() {
            "a device (a mount over the key's name?)"
        } else if t.is_fifo() {
            "a FIFO"
        } else if t.is_socket() {
            "a socket"
        } else if t.is_dir() {
            "a directory"
        } else {
            "a special file"
        };
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("not a regular file: {what}"),
        ));
    }
    let mut buf = Vec::new();
    f.take(MAX_KEY_FILE_BYTES + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_KEY_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("larger than {MAX_KEY_FILE_BYTES} bytes"),
        ));
    }
    String::from_utf8(buf)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "not UTF-8 text"))
}

fn parse_signing_key(raw: &str) -> Result<SigningKey> {
    let trimmed = raw.strip_suffix('\n').unwrap_or(raw);
    if trimmed.contains('\n') || trimmed.contains('\r') {
        return Err(anyhow!(
            "signing key file has embedded newline — expected single-line hex"
        ));
    }
    if trimmed.len() != SIGNING_KEY_HEX_LEN {
        return Err(anyhow!(
            "signing key has {} hex chars (expected {SIGNING_KEY_HEX_LEN})",
            trimmed.len()
        ));
    }
    // R11b (lab PR 262, review #466 F1/F4): where, never which character —
    // the error reaches the journal
    let bytes = hex::decode(trimmed).map_err(|e| match e {
        hex::FromHexError::InvalidHexCharacter { index, .. } => {
            anyhow!("signing key is not valid hex (character {index})")
        }
        _ => anyhow!("signing key is not valid hex"),
    })?;
    let mut secret = [0u8; SECRET_KEY_LENGTH];
    secret.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&secret))
}

fn persist_signing_key_atomically(path: &Path, key: &SigningKey) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::DirBuilder::new()
                .mode(PARENT_DIR_MODE)
                .recursive(true)
                .create(parent)
                .with_context(|| format!("creating signing-key parent dir {}", parent.display()))?;
        }
    }
    let tmp_path = tmp_path_for(path);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(SIGNING_KEY_FILE_MODE)
            .open(&tmp_path)
            .with_context(|| format!("creating signing-key tmpfile {}", tmp_path.display()))?;
        let mut line = hex::encode(key.to_bytes());
        line.push('\n');
        f.write_all(line.as_bytes())
            .with_context(|| format!("writing signing-key bytes to {}", tmp_path.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp_path.display()))?;
    }
    fs::rename(&tmp_path, path)
        .with_context(|| format!("renaming {} → {}", tmp_path.display(), path.display()))?;
    Ok(())
}

fn tmp_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

/// The chains sign with the agent's key.
impl ChainSigner for AgentSigningKey {
    type Host = crate::chain_host_linux::LinuxHost;
    fn sign(&self, msg: &[u8]) -> Signature {
        AgentSigningKey::sign(self, msg)
    }
    fn verifying_key(&self) -> VerifyingKey {
        AgentSigningKey::verifying_key(self)
    }
}

/// Load the verifying key the way the boot does before the attach: the
/// signing key if readable, else its published public half. (From
/// `crate::chain_anchor`, R04a, lab PR 241: it reads key files.)
pub fn boot_verifying_key(signing_key_file: &Path) -> Option<VerifyingKey> {
    match read_signing_key(signing_key_file) {
        Ok(k) => Some(k.verifying_key()),
        Err(_) => read_verifying_key(&verifying_key_path(signing_key_file)).ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn fresh_paths() -> (TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().expect("create tempdir");
        let key_path = dir.path().join("agent.sig.key");
        let log_path = dir.path().join("audit.log");
        (dir, key_path, log_path)
    }

    /// External audit EVD-001: the agent publishes the public half next to
    /// its key (0444), rewrites it when it says something else, and a
    /// reader gets the same verifying key from it.
    #[test]
    fn the_public_half_is_published_next_to_the_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let key_path = dir.path().join("agent.sig.key");
        let key = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let pub_path = verifying_key_path(&key_path);
        assert_eq!(pub_path, dir.path().join("agent.sig.pub"));
        assert_eq!(read_verifying_key(&pub_path).unwrap(), key.verifying_key());
        let mode = fs::metadata(&pub_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o444);
        // a wrong public half is replaced at the next load
        fs::remove_file(&pub_path).unwrap();
        fs::write(&pub_path, "00".repeat(32)).unwrap();
        let again = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        assert_eq!(
            read_verifying_key(&pub_path).unwrap(),
            again.verifying_key()
        );
    }

    #[test]
    fn signing_key_fresh_gen_writes_mode_0400() {
        let (_dir, key_path, _) = fresh_paths();
        let _key = AgentSigningKey::load_or_bootstrap(&key_path)
            .expect("bootstrap should succeed on missing path");
        let meta = fs::metadata(&key_path).expect("file should exist");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o400,
            "signing key file should be mode 0400"
        );
        let raw = fs::read_to_string(&key_path).unwrap();
        let trimmed = raw.strip_suffix('\n').unwrap_or(&raw);
        assert_eq!(trimmed.len(), SIGNING_KEY_HEX_LEN);
        assert!(trimmed.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn signing_key_reuses_existing_file() {
        let (_dir, key_path, _) = fresh_paths();
        let first = AgentSigningKey::load_or_bootstrap(&key_path).expect("first bootstrap");
        let second = AgentSigningKey::load_or_bootstrap(&key_path).expect("second load");
        assert_eq!(
            first.inner.to_bytes(),
            second.inner.to_bytes(),
            "second load must return the persisted key bytes"
        );
    }

    #[test]
    fn signing_key_corrupted_file_errors_without_regen() {
        let (_dir, key_path, _) = fresh_paths();
        fs::write(&key_path, "definitely not hex\n").unwrap();
        let err = AgentSigningKey::load_or_bootstrap(&key_path)
            .expect_err("corrupted file must hard-error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("corrupted") || msg.contains("not valid hex") || msg.contains("hex chars"),
            "error must mention corruption / hex problem; got: {msg}"
        );
        // The corrupted file must remain untouched — no silent
        // regeneration that would invalidate the audit log.
        let after = fs::read_to_string(&key_path).unwrap();
        assert_eq!(after, "definitely not hex\n");
    }

    /// Lab PR 265 (review #466 F4-bis): an absent key beside its public half
    /// is an error, and nothing is written; without the public half it is
    /// minted (a first boot), and the public half published.
    #[test]
    fn an_absent_key_beside_its_public_half_is_not_minted() {
        let (dir, key_path, _) = fresh_paths();
        let first = AgentSigningKey::load_or_bootstrap(&key_path).expect("first boot");
        let public = verifying_key_path(&key_path);
        let published = fs::read(&public).unwrap();
        fs::remove_file(&key_path).unwrap();
        let err = AgentSigningKey::load_or_bootstrap(&key_path).expect_err("not minted");
        let msg = format!("{err:#}");
        assert!(msg.contains("refusing to mint"), "{msg}");
        assert!(!key_path.exists(), "a key was minted");
        assert_eq!(
            fs::read(&public).unwrap(),
            published,
            "the public half rewritten"
        );
        // an empty file at the public half's name counts the same
        fs::remove_file(&public).unwrap();
        fs::write(&public, "").unwrap();
        assert!(AgentSigningKey::load_or_bootstrap(&key_path).is_err());
        assert!(!key_path.exists());
        // both gone: a first boot again, a new key
        fs::remove_file(&public).unwrap();
        let again = AgentSigningKey::load_or_bootstrap(&key_path).expect("minted");
        assert_ne!(again.verifying_key(), first.verifying_key());
        assert_eq!(read_verifying_key(&public).unwrap(), again.verifying_key());
        drop(dir);
    }

    /// R11b (lab PR 262, review #466 F4): what sits at the key's name and is
    /// not a key is an error that says what it is — never an empty key, a
    /// wait on a FIFO, or a quote of the content: empty (what a bind mount
    /// of `/dev/null` reads), `/dev/null` itself (through a link here, as a
    /// mount would show it), a FIFO, a directory, a key with one character
    /// wrong.
    #[test]
    fn what_is_not_a_key_is_an_error_without_its_content() {
        let (dir, key_path, _) = fresh_paths();
        let err = |p: &Path| {
            let p = p.to_path_buf();
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(
                    AgentSigningKey::load_or_bootstrap(&p)
                        .map(drop)
                        .map_err(|e| format!("{e:#}")),
                );
            });
            rx.recv_timeout(std::time::Duration::from_secs(5))
                .expect("blocked for 5 s")
                .expect_err("not a key")
        };
        fs::write(&key_path, "").unwrap();
        assert!(err(&key_path).contains("0 hex chars"), "{}", err(&key_path));
        let null = dir.path().join("null.key");
        std::os::unix::fs::symlink("/dev/null", &null).unwrap();
        assert!(err(&null).contains("a device"), "{}", err(&null));
        let fifo = dir.path().join("fifo.key");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(err(&fifo).contains("a FIFO"), "{}", err(&fifo));
        let d = dir.path().join("dir.key");
        fs::create_dir(&d).unwrap();
        assert!(err(&d).contains("a directory"), "{}", err(&d));
        let secret = format!("{}#{}\n", "ab".repeat(16), "cd".repeat(15) + "e");
        let wrong = dir.path().join("wrong.key");
        fs::write(&wrong, &secret).unwrap();
        let e = err(&wrong);
        assert!(e.contains("not valid hex (character 32)"), "{e}");
        assert!(!e.contains('#') && !e.contains(&"ab".repeat(16)), "{e}");
        // none of them was replaced by a fresh key
        assert_eq!(fs::read_to_string(&key_path).unwrap(), "");
        assert_eq!(fs::read_to_string(&wrong).unwrap(), secret);
    }
}
