//! Per-install agent identity (Tappa 8 design §6.5, commit A3).
//!
//! Every running agent owns a stable 16-byte UUID — the **agent
//! install UUID** — written exactly once at first start to
//! `/etc/northnarrow/agent_id` and re-read on every subsequent boot.
//! The value participates in the Tappa 8 signed-payload binding
//! (design §6.4 layer 3, [`common::wire::admin_signed_payload::SignedPayload::agent_id`]):
//! a captured admin signature replayed against a different agent
//! install fails because the payload's `agent_id` field will no
//! longer match the verifier's value.
//!
//! ## File format
//!
//! ```text
//! 32 hex chars + '\n'
//! ```
//!
//! Exactly the lowercase hex form of the 16 random bytes the agent
//! minted at bootstrap, plus one trailing newline so a human running
//! `cat /etc/northnarrow/agent_id` sees a tidy single line.
//! [`load_or_bootstrap`] accepts the trailing newline as optional
//! (some editors strip it); anything else — wrong length, non-hex,
//! multi-line, leading whitespace — is rejected as corruption.
//!
//! Permissions:
//! - File mode `0644` (design §6.5).
//! - Directory mode `0755`.
//! - Both root-owned by virtue of the agent being root at write
//!   time; we do not chown.
//!
//! ## Bootstrap policy
//!
//! - Path missing → mint 16 fresh bytes from `OsRng`, atomic-write
//!   (tmpfile + `rename(2)`), return.
//! - Path present and well-formed → read, return.
//! - Path present but corrupted → return error; the operator must
//!   investigate. We deliberately do NOT silently regenerate, because
//!   a regenerated UUID would silently invalidate every outstanding
//!   admin signature minted against the old one, and the situations
//!   that produce a corrupted `agent_id` are exactly the situations
//!   where an audit trail of "who changed it and when" is most
//!   needed.
//!
//! ## Why this commit doesn't wire into `AdminAuth`
//!
//! A3 is the bootstrap primitive. The agent's verify path doesn't
//! consume `agent_id` until A4 (timestamp skew + agent_id binding
//! reach the `verify_unlock` site simultaneously). Keeping A3 a pure
//! standalone module lets the test surface stay tiny (~3 design-
//! required tests) and lets A4 own the AdminAuth integration commit.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use tracing::info;

/// Default location of the persisted agent install UUID. Mirrors the
/// `/etc/northnarrow/` install layout the rest of the agent uses
/// (admin.pub today; audit.log and agent.sig.key in later A-series
/// commits).
pub const DEFAULT_AGENT_ID_PATH: &str = "/etc/northnarrow/agent_id";

/// Width of the raw agent_id in bytes. Bound by the design (§6.5
/// "16-byte UUID") and by the
/// [`common::wire::admin_signed_payload::SignedPayload::agent_id`]
/// array type. Changing this is a wire-protocol break.
pub const AGENT_ID_LEN: usize = 16;

/// Width of the on-disk hex encoding of one [`AGENT_ID_LEN`]-byte
/// value. Used by the parser as the strict length pre-check before
/// hex decoding (avoids a hex error for an obviously-truncated file).
const HEX_LEN: usize = AGENT_ID_LEN * 2;

/// File mode for the persisted agent_id. World-readable per design
/// §6.5 — the value is non-secret; what matters is that root is the
/// only writer (enforced by [`PARENT_DIR_MODE`] + the post-LSM
/// `/etc/northnarrow/` widening tracked as design Q1).
const FILE_MODE: u32 = 0o644;

/// Mode for the parent directory if it does not already exist.
/// `0755` is the conventional `/etc/<vendor>/` layout — root writes,
/// world reads.
const PARENT_DIR_MODE: u32 = 0o755;

/// Load the persisted agent_id from `path`, OR mint a fresh one and
/// persist it if the file is absent. Returns the 16-byte value on
/// success.
///
/// Atomicity: a fresh-mint write goes through `<path>.tmp` + `rename(2)`
/// so a crash mid-write never leaves a half-formed `agent_id` on disk
/// for the next boot to misinterpret. The tmp file shares the parent
/// directory so `rename` is `EXDEV`-free.
///
/// Errors when:
/// - the file exists but is corrupted (wrong length, non-hex, etc.) —
///   the operator must investigate before the agent can run with an
///   ambiguous identity (see module doc-comment "Bootstrap policy");
/// - the file system refuses our write (`EROFS`, `ENOSPC`, missing
///   parent that we can't create);
/// - the OS CSPRNG cannot provide entropy (vanishingly rare; would
///   typically only happen on a broken kernel build).
pub fn load_or_bootstrap(path: &Path) -> Result<[u8; AGENT_ID_LEN]> {
    match fs::read_to_string(path) {
        Ok(content) => {
            let id = parse(&content).with_context(|| {
                format!(
                    "agent_id file {} present but corrupted — refuse to silently \
                     regenerate; remove the file deliberately if you intend to mint \
                     a new identity",
                    path.display()
                )
            })?;
            info!(
                target: "agent_id",
                path = %path.display(),
                "reusing existing agent_id"
            );
            Ok(id)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let id = mint_random()?;
            persist_atomically(path, &id)?;
            info!(
                target: "agent_id",
                path = %path.display(),
                "bootstrapped fresh agent_id"
            );
            Ok(id)
        }
        Err(e) => Err(anyhow!(e).context(format!("reading {}", path.display()))),
    }
}

/// Parse a file body into a 16-byte agent_id. Trailing newline is
/// optional (handles both `echo` and tidier writers). Returns an
/// error on anything that isn't exactly `[HEX_LEN]` lowercase- or
/// uppercase-hex chars (the hex crate is case-insensitive on
/// decode; we accept both for operator convenience, write
/// lowercase ourselves).
fn parse(raw: &str) -> Result<[u8; AGENT_ID_LEN]> {
    // Single trailing newline is part of the canonical encoding; we
    // strip exactly one. Two trailing newlines, or a leading newline,
    // or any embedded whitespace, is treated as corruption — the
    // canonical writer never produces such bytes.
    let trimmed = raw.strip_suffix('\n').unwrap_or(raw);
    if trimmed.contains('\n') || trimmed.contains('\r') {
        return Err(anyhow!(
            "agent_id file has embedded newline — expected single-line hex"
        ));
    }
    if trimmed.len() != HEX_LEN {
        return Err(anyhow!(
            "agent_id has {} hex chars (expected {HEX_LEN})",
            trimmed.len()
        ));
    }
    let bytes = hex::decode(trimmed).map_err(|e| anyhow!("agent_id is not valid hex: {e}"))?;
    let mut out = [0u8; AGENT_ID_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Mint 16 fresh CSPRNG bytes via `OsRng`. Same source the rest of
/// the crypto path (admin_auth nonces, ed25519 keygen) uses — we
/// never reach for the thread-local `rand::thread_rng()` for
/// security-relevant material.
fn mint_random() -> Result<[u8; AGENT_ID_LEN]> {
    let mut buf = [0u8; AGENT_ID_LEN];
    OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|e| anyhow!("OsRng failed to provide entropy: {e}"))?;
    Ok(buf)
}

/// Write `id` to `path` atomically. The tempfile sits next to the
/// target so `rename(2)` is a single inode swap inside one
/// filesystem; we never see a partial write at the final path even
/// across a SIGKILL.
fn persist_atomically(path: &Path, id: &[u8; AGENT_ID_LEN]) -> Result<()> {
    // Make sure the parent directory exists. `create_dir_all` is
    // idempotent on AlreadyExists. Mode 0755 applies only on
    // create; an existing dir's permissions are deliberately left
    // alone (operator may have tightened them on purpose).
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::DirBuilder::new()
                .mode(PARENT_DIR_MODE)
                .recursive(true)
                .create(parent)
                .with_context(|| format!("creating agent_id parent dir {}", parent.display()))?;
        }
    }

    let tmp_path = tmp_path_for(path);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&tmp_path)
            .with_context(|| format!("creating tmpfile {}", tmp_path.display()))?;
        let mut line = hex::encode(id);
        line.push('\n');
        f.write_all(line.as_bytes())
            .with_context(|| format!("writing agent_id bytes to {}", tmp_path.display()))?;
        // fsync the file so the bytes are durable on the platter
        // before the rename publishes them. A crash between
        // rename(2) and a missed fsync would otherwise show an
        // empty / zero-filled file on the next boot, which is
        // exactly the corruption parse() would reject and the
        // operator would have to clean up by hand.
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp_path.display()))?;
    }
    fs::rename(&tmp_path, path)
        .with_context(|| format!("renaming {} → {}", tmp_path.display(), path.display()))?;
    Ok(())
}

/// `<path>.tmp` next to the target. Per-process collision-free even
/// without a PID/uniqifier because `create_new` refuses to clobber,
/// and we are the only writer; a stale `.tmp` left by a prior
/// crashed agent surfaces as `EEXIST` and the operator deletes it.
fn tmp_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn fresh_path() -> (TempDir, PathBuf) {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("agent_id");
        (dir, path)
    }

    // ── A3 required tests ──────────────────────────────────────────

    /// Required A3 test 1 ("fresh-gen"): a missing file is created
    /// with 16 valid random bytes, mode 0644, hex+newline shape.
    #[test]
    fn load_or_bootstrap_generates_fresh_when_missing() {
        let (_dir, path) = fresh_path();
        assert!(!path.exists());

        let id = load_or_bootstrap(&path).expect("bootstrap");
        assert_eq!(id.len(), AGENT_ID_LEN);
        assert!(
            id.iter().any(|&b| b != 0),
            "agent_id should not be all zeros (entropy sanity)"
        );

        // File now exists, with the canonical hex+newline format.
        let raw = fs::read_to_string(&path).expect("read");
        assert_eq!(raw.len(), HEX_LEN + 1, "expected 32 hex chars + '\\n'");
        assert!(raw.ends_with('\n'));
        assert_eq!(
            raw.trim_end_matches('\n'),
            hex::encode(id),
            "on-disk content must round-trip exactly"
        );

        // Mode is 0644 (umask masking the bits is not in scope —
        // OpenOptions::mode is honoured by the kernel directly).
        let meta = fs::metadata(&path).expect("metadata");
        assert_eq!(
            meta.permissions().mode() & 0o7777,
            FILE_MODE,
            "agent_id file should be mode 0644"
        );

        // No stray .tmp left after the atomic publish.
        let tmp = tmp_path_for(&path);
        assert!(
            !tmp.exists(),
            "atomic write must clean up its tmp file: {}",
            tmp.display()
        );
    }

    /// Required A3 test 2 ("reuse-existing"): a present, well-formed
    /// file is loaded byte-identically, with the file unchanged.
    #[test]
    fn load_or_bootstrap_reuses_existing_file_without_modifying_it() {
        let (_dir, path) = fresh_path();

        // First call writes a fresh file…
        let first = load_or_bootstrap(&path).expect("bootstrap");
        let raw_before = fs::read_to_string(&path).expect("read");
        let mtime_before = fs::metadata(&path).unwrap().modified().unwrap();

        // …second call returns the same bytes…
        let second = load_or_bootstrap(&path).expect("reuse");
        assert_eq!(first, second, "reuse must return byte-identical agent_id");

        // …and the on-disk file is untouched.
        let raw_after = fs::read_to_string(&path).expect("read");
        assert_eq!(
            raw_before, raw_after,
            "file content must not change on reuse"
        );
        let mtime_after = fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(mtime_before, mtime_after, "mtime must not change on reuse");
    }

    /// Required A3 test 3 ("file-corrupted"): every corruption shape
    /// the parser can detect must surface as an Err — load_or_bootstrap
    /// MUST NOT silently regenerate, because that would invalidate
    /// every outstanding admin signature minted against the old
    /// agent_id without any operator-visible trail.
    #[test]
    fn load_or_bootstrap_rejects_every_corruption_shape() {
        for (label, content) in [
            ("empty", ""),
            ("too short", "abcd"),
            (
                "too long by one nibble",
                "0123456789abcdef0123456789abcdef0",
            ),
            ("right length, non-hex", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
            ("leading whitespace", " 0123456789abcdef0123456789abcdef"),
            (
                "trailing extra newline",
                "0123456789abcdef0123456789abcdef\n\n",
            ),
            ("embedded newline", "0123456789abcdef\n0123456789abcdef"),
            ("carriage return", "0123456789abcdef0123456789abcdef\r\n"),
        ] {
            let (_dir, path) = fresh_path();
            fs::write(&path, content).unwrap();
            let err = load_or_bootstrap(&path).unwrap_err();
            // Make sure the error mentions the file path so the
            // operator can find what to investigate.
            let chain = format!("{err:#}");
            assert!(
                chain.contains("agent_id"),
                "[{label}] error should reference agent_id: {chain}"
            );
        }
    }

    // ── Supplementary tests ────────────────────────────────────────

    /// Two consecutive fresh bootstraps on different paths must
    /// produce different agent_ids — proof OsRng isn't returning
    /// a static value.
    #[test]
    fn two_fresh_bootstraps_produce_distinct_ids() {
        let (_a_dir, a_path) = fresh_path();
        let (_b_dir, b_path) = fresh_path();
        let a = load_or_bootstrap(&a_path).unwrap();
        let b = load_or_bootstrap(&b_path).unwrap();
        // The probability of a 16-byte collision from OsRng is
        // 2^-128; one assertion is sufficient.
        assert_ne!(a, b, "OsRng should not return the same bytes twice");
    }

    /// Parser accepts both uppercase and lowercase hex on read
    /// (writer always emits lowercase). Documents the case-insensitive
    /// contract so an operator who edits the file in a hex tool that
    /// uppercases doesn't get a spurious "corrupted" error.
    #[test]
    fn parser_accepts_uppercase_hex_for_operator_convenience() {
        let raw = "ABCDEF0123456789ABCDEF0123456789\n";
        let id = parse(raw).expect("uppercase hex parses");
        assert_eq!(
            id,
            hex::decode("abcdef0123456789abcdef0123456789")
                .unwrap()
                .as_slice()
        );
    }

    /// The bootstrap path tolerates a missing parent directory —
    /// fresh /etc/northnarrow installs are common on first deploy.
    /// We create the parent with mode 0755 if it isn't there.
    #[test]
    fn bootstrap_creates_parent_directory_if_absent() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("etc/northnarrow/agent_id");
        assert!(!nested.parent().unwrap().exists());

        let _ = load_or_bootstrap(&nested).expect("bootstrap with missing parent");
        assert!(nested.exists());
        assert!(nested.parent().unwrap().exists());
    }

    /// Direct unit test of the parser path: a stray `\r` is never
    /// produced by the canonical writer and is treated as corruption.
    /// Locked here so a future "be lenient about CRLF" change is a
    /// conscious choice rather than an accidental regression.
    #[test]
    fn parser_rejects_carriage_return_endings() {
        let crlf = "0123456789abcdef0123456789abcdef\r\n";
        assert!(parse(crlf).is_err(), "CRLF must be rejected");
    }
}
