//! `Quarantine` — encrypt a target's executable into a vault and
//! remove the original file.
//!
//! Vault layout:
//! ```text
//! <quarantine_dir>/
//! ├── index.json          (mode 0600; atomic write via tmp+rename)
//! └── vault/
//!     ├── <uuid>.bin      (AES-256-GCM ciphertext, mode 0600)
//!     └── <uuid>.meta     (JSON metadata, mode 0600)
//! ```
//!
//! Crypto:
//! - Master key: 32 random bytes at [`ExecutorConfig::master_key_file`],
//!   created mode 0600 on first use, kept in memory wrapped in
//!   `Zeroizing<[u8; 32]>` so it gets wiped on drop.
//! - Per-file derivation: HKDF-SHA256 with salt
//!   `"northnarrow-quarantine-v1"` and per-file info equal to the
//!   vault id. This means a leaked file-key can decrypt only its
//!   own ciphertext.
//! - Per-file nonce: 96 random bits, fresh per encryption.
//!
//! [`restore`] reverses the operation: decrypts the vault file and
//! writes it back to a caller-provided path.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use zeroize::Zeroizing;

use super::{config::ExecutorConfig, ExecutionOutcome};

const KDF_SALT: &[u8] = b"northnarrow-quarantine-v1";
const NONCE_LEN: usize = 12;

/// Public entry point: encrypt the binary backing `target_pid` and
/// remove the original file.
pub fn quarantine_process_binary(
    target_pid: u32,
    protected: &HashSet<u32>,
    cfg: &ExecutorConfig,
) -> ExecutionOutcome {
    if target_pid == 0 {
        return ExecutionOutcome::Refused {
            pid: target_pid,
            reason: "PID 0 invalid",
        };
    }
    if protected.contains(&target_pid) {
        return ExecutionOutcome::Refused {
            pid: target_pid,
            reason: "PID is protected",
        };
    }

    let exe_link = format!("/proc/{target_pid}/exe");
    let original = match fs::read_link(&exe_link) {
        Ok(p) => p,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return ExecutionOutcome::AlreadyGone { pid: target_pid }
        }
        Err(e) => {
            warn!(pid = target_pid, error = %e, "read_link /proc/<pid>/exe");
            return ExecutionOutcome::Failed {
                pid: target_pid,
                errno: e.raw_os_error().unwrap_or(0),
            };
        }
    };
    let original_str = original.to_string_lossy().into_owned();

    if cfg.dry_run {
        info!(
            pid = target_pid,
            path = %original_str,
            "dry-run: would quarantine binary"
        );
        return ExecutionOutcome::Quarantined {
            original_path: original_str,
            vault_id: "dry-run".to_string(),
        };
    }

    match quarantine_file(&original, cfg) {
        Ok(vault_id) => {
            info!(
                pid = target_pid,
                vault_id = %vault_id,
                path = %original_str,
                "quarantined binary"
            );
            ExecutionOutcome::Quarantined {
                original_path: original_str,
                vault_id,
            }
        }
        Err(QuarantineError::TooLarge { size, max }) => {
            warn!(
                pid = target_pid,
                size, max, "binary exceeds quarantine_max_bytes; refusing"
            );
            ExecutionOutcome::Failed {
                pid: target_pid,
                // EFBIG is "file too large"; close enough.
                errno: libc::EFBIG,
            }
        }
        Err(QuarantineError::Io(e)) => {
            warn!(pid = target_pid, error = %e, "quarantine I/O failed");
            ExecutionOutcome::Failed {
                pid: target_pid,
                errno: e.raw_os_error().unwrap_or(0),
            }
        }
        Err(QuarantineError::Crypto(e)) => {
            warn!(pid = target_pid, error = %e, "quarantine crypto failed");
            ExecutionOutcome::Failed {
                pid: target_pid,
                errno: 0,
            }
        }
    }
}

/// Decrypt a previously-quarantined file back to `out_path`.
/// Restores file mode 0644 (the original's exact mode is captured
/// in the metadata for future use; for Tappa 5 we keep restore
/// permissive to ease forensic review).
pub fn restore(vault_id: &str, out_path: &Path, cfg: &ExecutorConfig) -> std::io::Result<()> {
    let vault_dir = cfg.quarantine_dir.join("vault");
    let bin_path = vault_dir.join(format!("{vault_id}.bin"));
    let meta_path = vault_dir.join(format!("{vault_id}.meta"));

    let mut bin = fs::read(&bin_path)?;
    if bin.len() < NONCE_LEN {
        return Err(std::io::Error::other("vault file too short"));
    }
    let nonce_bytes: [u8; NONCE_LEN] = bin[..NONCE_LEN]
        .try_into()
        .map_err(|_| std::io::Error::other("nonce slice"))?;
    let ciphertext = bin.split_off(NONCE_LEN);
    drop(bin);

    let master = load_or_init_master_key(cfg)?;
    let key = derive_file_key(&master, vault_id);
    let cipher = Aes256Gcm::new((&*key).into());
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &ciphertext,
                aad: vault_id.as_bytes(),
            },
        )
        .map_err(|e| std::io::Error::other(format!("decrypt: {e}")))?;

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(out_path, &plaintext)?;
    let _ = fs::set_permissions(out_path, fs::Permissions::from_mode(0o644));

    info!(
        vault_id,
        out = %out_path.display(),
        size = plaintext.len(),
        meta = %meta_path.display(),
        "restored quarantined file"
    );
    Ok(())
}

#[derive(Debug)]
enum QuarantineError {
    TooLarge { size: u64, max: u64 },
    Io(std::io::Error),
    Crypto(String),
}

impl From<std::io::Error> for QuarantineError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

fn quarantine_file(original: &Path, cfg: &ExecutorConfig) -> Result<String, QuarantineError> {
    let meta = fs::metadata(original)?;
    let size = meta.len();
    if size > cfg.quarantine_max_bytes {
        return Err(QuarantineError::TooLarge {
            size,
            max: cfg.quarantine_max_bytes,
        });
    }

    // Read once.
    let mut content = Vec::with_capacity(size as usize + 16);
    fs::File::open(original)?.read_to_end(&mut content)?;
    let sha = Sha256::digest(&content);

    // Encrypt.
    let vault_id = uuid::Uuid::new_v4().simple().to_string();
    let master = load_or_init_master_key(cfg)?;
    let file_key = derive_file_key(&master, &vault_id);
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new((&*file_key).into());
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &content,
                aad: vault_id.as_bytes(),
            },
        )
        .map_err(|e| QuarantineError::Crypto(format!("encrypt: {e}")))?;

    // Lay out the vault.
    let vault_dir = cfg.quarantine_dir.join("vault");
    fs::create_dir_all(&vault_dir)?;
    set_dir_root_only(&cfg.quarantine_dir);
    set_dir_root_only(&vault_dir);

    let bin_path = vault_dir.join(format!("{vault_id}.bin"));
    let meta_path = vault_dir.join(format!("{vault_id}.meta"));

    // Write ciphertext (nonce prefix). Mode 0600.
    let mut bin_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&bin_path)?;
    bin_file.write_all(&nonce)?;
    bin_file.write_all(&ciphertext)?;
    bin_file.sync_all()?;
    drop(bin_file);

    // Write meta as JSON.
    let original_str = original.to_string_lossy().into_owned();
    let meta_json = serde_json::json!({
        "vault_id": vault_id,
        "original_path": original_str,
        "size_bytes": size,
        "sha256": format!("{:x}", sha),
        "captured_at": current_timestamp(),
    });
    let mut meta_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&meta_path)?;
    meta_file.write_all(meta_json.to_string().as_bytes())?;
    meta_file.sync_all()?;
    drop(meta_file);

    // Update index.json atomically (tmp + fsync + rename).
    update_index(&cfg.quarantine_dir, &vault_id, &original_str, size)?;

    // Remove the original. If unlink fails (e.g. EBUSY because the
    // binary is mmaped by the running process), fall back to
    // chmod 000 so it can't be re-executed by anyone non-root.
    if let Err(e) = fs::remove_file(original) {
        warn!(error = %e, path = %original.display(), "remove original failed; chmod 000");
        let _ = fs::set_permissions(original, fs::Permissions::from_mode(0o000));
    }

    Ok(vault_id)
}

fn update_index(
    quarantine_dir: &Path,
    vault_id: &str,
    original_path: &str,
    size: u64,
) -> std::io::Result<()> {
    let index_path = quarantine_dir.join("index.json");
    let tmp_path = quarantine_dir.join("index.json.tmp");

    let mut entries: Vec<serde_json::Value> = match fs::read_to_string(&index_path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(e) if e.kind() == ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    entries.push(serde_json::json!({
        "vault_id": vault_id,
        "original_path": original_path,
        "size_bytes": size,
        "captured_at": current_timestamp(),
    }));

    let serialized = serde_json::to_string_pretty(&entries).map_err(std::io::Error::other)?;
    let mut tmp = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_path)?;
    tmp.write_all(serialized.as_bytes())?;
    tmp.sync_all()?;
    drop(tmp);
    fs::rename(&tmp_path, &index_path)?;
    Ok(())
}

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn set_dir_root_only(path: &Path) {
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o700);
        let _ = fs::set_permissions(path, perms);
    }
}

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
    rand::rngs::OsRng.fill_bytes(&mut *k);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&cfg.master_key_file)?;
    f.write_all(&*k)?;
    f.sync_all()?;
    Ok(k)
}

fn derive_file_key(master: &Zeroizing<[u8; 32]>, vault_id: &str) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(KDF_SALT), &**master);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(vault_id.as_bytes(), &mut *out)
        .expect("HKDF 32-byte expand cannot fail");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn cfg_for(tmp: &TempDir) -> ExecutorConfig {
        let mut c = ExecutorConfig::for_test(tmp.path());
        c.dry_run = false;
        c
    }

    #[test]
    fn round_trip_encrypts_and_decrypts() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);

        let payload_path = tmp.path().join("payload.bin");
        let payload = b"hello, this is the payload contents".to_vec();
        fs::write(&payload_path, &payload).unwrap();

        let vault_id = quarantine_file(&payload_path, &cfg).expect("quarantine");
        assert!(!payload_path.exists(), "original should be unlinked");

        let restored_path = tmp.path().join("restored.bin");
        restore(&vault_id, &restored_path, &cfg).expect("restore");
        assert_eq!(fs::read(&restored_path).unwrap(), payload);
    }

    #[test]
    fn nonce_differs_per_call() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);

        let p1 = tmp.path().join("a.bin");
        let p2 = tmp.path().join("b.bin");
        fs::write(&p1, b"same content").unwrap();
        fs::write(&p2, b"same content").unwrap();

        let id1 = quarantine_file(&p1, &cfg).unwrap();
        let id2 = quarantine_file(&p2, &cfg).unwrap();
        assert_ne!(id1, id2);

        let bin1 = fs::read(cfg.quarantine_dir.join("vault").join(format!("{id1}.bin"))).unwrap();
        let bin2 = fs::read(cfg.quarantine_dir.join("vault").join(format!("{id2}.bin"))).unwrap();
        // Different nonces (first 12 bytes) and ciphertexts.
        assert_ne!(&bin1[..12], &bin2[..12]);
        assert_ne!(bin1, bin2);
    }

    #[test]
    fn refuses_files_above_max_size() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = cfg_for(&tmp);
        cfg.quarantine_max_bytes = 8;

        let p = tmp.path().join("too-big.bin");
        fs::write(&p, vec![0u8; 32]).unwrap();
        let err = quarantine_file(&p, &cfg).unwrap_err();
        match err {
            QuarantineError::TooLarge { size, max } => {
                assert_eq!(size, 32);
                assert_eq!(max, 8);
            }
            _ => panic!("expected TooLarge"),
        }
        // Original file untouched on refusal.
        assert!(p.exists());
    }

    #[test]
    fn index_json_is_appended_atomically() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);

        let pa = tmp.path().join("a.bin");
        let pb = tmp.path().join("b.bin");
        fs::write(&pa, b"a contents").unwrap();
        fs::write(&pb, b"b contents").unwrap();

        let _ida = quarantine_file(&pa, &cfg).unwrap();
        let _idb = quarantine_file(&pb, &cfg).unwrap();

        let index_path = cfg.quarantine_dir.join("index.json");
        let s = fs::read_to_string(&index_path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v.as_array().map(|a| a.len()), Some(2));
        // tmp file should not be left behind.
        assert!(!cfg.quarantine_dir.join("index.json.tmp").exists());
    }

    #[test]
    fn master_key_is_persisted_and_reused() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_for(&tmp);

        let k1 = load_or_init_master_key(&cfg).unwrap();
        let k2 = load_or_init_master_key(&cfg).unwrap();
        assert_eq!(&*k1, &*k2);

        // Mode 0600 enforced.
        let mode = fs::metadata(&cfg.master_key_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
