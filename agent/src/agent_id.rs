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
//! - Path missing → mint 16 fresh bytes from `OsRng`, write them with
//!   [`crate::atomic_file::replace`] (no link followed, mode set on the
//!   descriptor, file and directory synced), return.
//! - Path present and well-formed → read, return.
//! - Path present but corrupted → return error; the operator must
//!   investigate. We deliberately do NOT silently regenerate, because
//!   a regenerated UUID would silently invalidate every outstanding
//!   admin signature minted against the old one, and the situations
//!   that produce a corrupted `agent_id` are exactly the situations
//!   where an audit trail of "who changed it and when" is most
//!   needed. The all-zero value is corruption too: it is the identity
//!   the test fixtures sign with, and `OsRng` never yields it.
//!
//! ## One read per boot, and who mints
//!
//! External audit MAIN-009 (NN-AUD-251): the agent reads the file once,
//! with [`resolve`], and hands the same [`AgentIdentity`] to the overlay
//! gate, the admin plane and the audit log. A file it cannot use is not a
//! reason to stop the EDR, nor to sign as the well-known zero: the boot
//! signs as a per-boot random id (never persisted), so nothing signed for
//! another install or for zero verifies, and records why in the signed
//! chain once the audit log is open.
//!
//! External audit EVD-020 (NN-AUD-282): a minted identity and an identity
//! that differs from the one the audit chain's last row carries are signed
//! rows ([`crate::audit::AuditLog::attest_identity`]): `agent_id_minted`,
//! and `integrity_drift` `agent_id_changed` with the old and the new id.
//!
//! External audit MAIN-010 (NN-AUD-252): only the agent mints.
//! `nn-admin` reads with [`load_existing`]: before the agent's first start
//! it fails naming the file and creates nothing.

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use tracing::{error, info};

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
/// value (the parser, `common::shutdown_marker::parse_agent_id`,
/// checks it before decoding).
#[cfg(test)]
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

/// Where this boot's identity came from (external audit MAIN-009,
/// EVD-020).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentitySource {
    /// Read from the file.
    Loaded,
    /// The file was absent: a fresh id was minted and persisted.
    Minted,
    /// The file could not be read, parsed or written (the reason): the id
    /// is a per-boot random one, never persisted.
    Unavailable(String),
}

impl IdentitySource {
    /// The word the signed rows and the journal use.
    pub fn label(&self) -> &'static str {
        match self {
            IdentitySource::Loaded => "loaded",
            IdentitySource::Minted => "minted",
            IdentitySource::Unavailable(_) => "unavailable",
        }
    }
}

/// The identity a boot signs as, read once ([`resolve`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentity {
    pub id: [u8; AGENT_ID_LEN],
    pub source: IdentitySource,
    /// The file it was read from, minted into, or could not be used.
    pub path: PathBuf,
}

/// The agent's one read of its identity at boot (external audit
/// MAIN-009). Never fails and never yields the all-zero id: a file that
/// cannot be used gives [`IdentitySource::Unavailable`] with a per-boot
/// random id, logged as an ERROR here and recorded in the signed chain
/// once the audit log is open ([`crate::audit::AuditLog::attest_identity`]).
/// Signed admin requests and overlays made for the install's id are then
/// refused for this boot; one signed for this boot's id (the `agent_id`
/// of its audit rows, written to a file passed with `--agent-id-file`)
/// opens a trusted-installer window to repair the file.
pub fn resolve(path: &Path) -> AgentIdentity {
    let (id, source) = match load_or_mint(path) {
        Ok((id, false)) => (id, IdentitySource::Loaded),
        Ok((id, true)) => (id, IdentitySource::Minted),
        Err(e) => {
            let reason = format!("{e:#}");
            let id = per_boot_id();
            error!(
                target: "agent_id",
                path = %path.display(),
                reason = %reason,
                boot_agent_id = %hex::encode(id),
                "agent_id UNAVAILABLE — this boot signs as a per-boot id, never persisted: \
                 signed admin requests and overlays made for the install's id are refused \
                 until the file is repaired"
            );
            (id, IdentitySource::Unavailable(reason))
        }
    };
    AgentIdentity {
        id,
        source,
        path: path.to_path_buf(),
    }
}

/// Load the persisted agent_id from `path`, OR mint a fresh one and
/// persist it if the file is absent. Returns the 16-byte value on
/// success. The agent's ([`resolve`]); `nn-admin` never mints
/// ([`load_existing`], external audit MAIN-010).
///
/// Atomicity and durability: a fresh mint goes through
/// [`crate::atomic_file::replace`] — `.agent_id.tmp` next to the target
/// (whatever sits at that name is removed, never followed), mode `0644`
/// set on the descriptor, the file synced, renamed into place and the
/// directory synced, so a crash never leaves a half-formed `agent_id`
/// and the rename survives a power loss (external audit EVD-020).
///
/// Errors when:
/// - the file exists but is corrupted (wrong length, non-hex, all
///   zeros, etc.) — the operator must investigate before the agent can
///   run with an ambiguous identity (see module doc-comment "Bootstrap
///   policy");
/// - the file system refuses our write (`EROFS`, `ENOSPC`, missing
///   parent that we can't create);
/// - the OS CSPRNG cannot provide entropy (vanishingly rare; would
///   typically only happen on a broken kernel build).
pub fn load_or_bootstrap(path: &Path) -> Result<[u8; AGENT_ID_LEN]> {
    load_or_mint(path).map(|(id, _)| id)
}

/// [`load_or_bootstrap`], and whether the id was minted now.
fn load_or_mint(path: &Path) -> Result<([u8; AGENT_ID_LEN], bool)> {
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
            Ok((id, false))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let id = mint_random()?;
            persist_atomically(path, &id)?;
            info!(
                target: "agent_id",
                path = %path.display(),
                "bootstrapped fresh agent_id"
            );
            Ok((id, true))
        }
        Err(e) => Err(anyhow!(e).context(format!("reading {}", path.display()))),
    }
}

/// Read an existing agent_id, never minting one (external audit MAIN-010,
/// NN-AUD-252): what `nn-admin` uses. A missing file means the agent has
/// not started yet on this host (or the path is wrong), and an id minted
/// here would be one the agent then adopts without a trace.
pub fn load_existing(path: &Path) -> Result<[u8; AGENT_ID_LEN]> {
    match fs::read_to_string(path) {
        Ok(content) => parse(&content)
            .with_context(|| format!("agent_id file {} present but corrupted", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
            "agent_id not found at {}: the agent creates it at its first start \
             (start northnarrow-agent once, or pass the right --agent-id-file)",
            path.display()
        ),
        Err(e) => Err(anyhow!(e).context(format!("reading agent_id {}", path.display()))),
    }
}

/// Parse a file body into a 16-byte agent_id. Trailing newline is
/// optional (handles both `echo` and tidier writers). Returns an
/// error on anything that isn't exactly `[HEX_LEN]` lowercase- or
/// uppercase-hex chars (the hex crate is case-insensitive on
/// decode; we accept both for operator convenience, write
/// lowercase ourselves), and on the all-zero id.
fn parse(raw: &str) -> Result<[u8; AGENT_ID_LEN]> {
    // Shared with the watchdog, which reads the same file to check the
    // install a shutdown was signed for (external audit WDG-001).
    let id = common::shutdown_marker::parse_agent_id(raw).map_err(|e| anyhow!(e))?;
    // External audit MAIN-009: zero is the identity the test fixtures sign
    // with and the old fallback used; OsRng does not mint it (2^-128).
    if id == [0u8; AGENT_ID_LEN] {
        bail!("agent_id is all zeros — the test fixtures' identity, never minted");
    }
    Ok(id)
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

/// The id of a boot whose file cannot be used (external audit MAIN-009):
/// random, never zero, never written. Without entropy from `OsRng` (a
/// broken kernel) it is derived from what differs per boot and per run,
/// still not the well-known zero.
fn per_boot_id() -> [u8; AGENT_ID_LEN] {
    if let Ok(id) = mint_random() {
        if id != [0u8; AGENT_ID_LEN] {
            return id;
        }
    }
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(fs::read("/proc/sys/kernel/random/boot_id").unwrap_or_default());
    h.update(std::process::id().to_le_bytes());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    h.update(nanos.to_le_bytes());
    let mut id = [0u8; AGENT_ID_LEN];
    id.copy_from_slice(&h.finalize()[..AGENT_ID_LEN]);
    id[0] |= 1;
    id
}

/// Write `id` to `path` with [`crate::atomic_file::replace`]: a crash
/// never shows a partial file at the final path, and the directory is
/// synced after the rename (external audit EVD-020: the rename used not
/// to be durable).
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
    let mut line = hex::encode(id);
    line.push('\n');
    crate::atomic_file::replace(path, line.as_bytes(), FILE_MODE)
        .with_context(|| format!("writing agent_id {}", path.display()))
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
        let tmp = path.with_file_name(".agent_id.tmp");
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

    // ── External audit MAIN-009 / EVD-020 / MAIN-010 ───────────────

    /// MAIN-009: the all-zero id — the test fixtures' identity and the old
    /// fallback — is corruption, not an identity (it used to load).
    #[test]
    fn an_all_zero_agent_id_is_refused_as_corruption() {
        let (_dir, path) = fresh_path();
        fs::write(&path, format!("{}\n", "0".repeat(HEX_LEN))).unwrap();
        let err = load_or_bootstrap(&path).unwrap_err();
        assert!(format!("{err:#}").contains("all zeros"), "{err:#}");
    }

    /// MAIN-009: the same for nn-admin's read and the agent's boot, which
    /// signs as a per-boot id instead.
    #[test]
    fn an_all_zero_agent_id_is_unavailable_at_boot() {
        let (_dir, path) = fresh_path();
        fs::write(&path, format!("{}\n", "0".repeat(HEX_LEN))).unwrap();
        assert!(load_existing(&path).is_err());
        let r = resolve(&path);
        assert!(matches!(r.source, IdentitySource::Unavailable(_)));
        assert_ne!(r.id, [0u8; AGENT_ID_LEN]);
    }

    /// MAIN-009: one read gives the id and where it came from; a file that
    /// cannot be used gives a per-boot id that is never zero, differs on
    /// every call and is never written.
    #[test]
    fn resolve_reports_the_source_and_never_falls_back_to_zero() {
        let (_dir, path) = fresh_path();
        let first = resolve(&path);
        assert_eq!(first.source, IdentitySource::Minted);
        assert_eq!(first.path, path);
        let again = resolve(&path);
        assert_eq!(again.source, IdentitySource::Loaded);
        assert_eq!(again.id, first.id);

        fs::write(&path, "not an id\n").unwrap();
        let a = resolve(&path);
        let b = resolve(&path);
        let IdentitySource::Unavailable(why) = &a.source else {
            panic!("corrupted file must be Unavailable: {:?}", a.source);
        };
        assert!(why.contains("agent_id"), "{why}");
        assert_ne!(a.id, [0u8; AGENT_ID_LEN]);
        assert_ne!(a.id, b.id, "a per-boot id is drawn fresh each time");
        assert_ne!(a.id, first.id);
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "not an id\n",
            "the corrupted file is left for the operator, not rewritten"
        );
        assert_eq!(a.source.label(), "unavailable");
    }

    /// MAIN-009: a mint that cannot be written is Unavailable too (the old
    /// code fell back to zero).
    #[test]
    fn resolve_without_a_writable_place_is_unavailable_not_zero() {
        let dir = TempDir::new().unwrap();
        // The parent "directory" is a file: the mint cannot be persisted.
        let blocker = dir.path().join("etc");
        fs::write(&blocker, "x").unwrap();
        let r = resolve(&blocker.join("agent_id"));
        assert!(matches!(r.source, IdentitySource::Unavailable(_)), "{r:?}");
        assert_ne!(r.id, [0u8; AGENT_ID_LEN]);
    }

    /// MAIN-010: nn-admin's read never mints — a missing file fails naming
    /// it and the agent's first start, and nothing is created (not even
    /// the directory).
    #[test]
    fn load_existing_never_mints() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("etc/northnarrow/agent_id");
        let err = load_existing(&path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains(&path.display().to_string()), "{msg}");
        assert!(msg.contains("first start"), "{msg}");
        assert!(!path.exists());
        assert!(!path.parent().unwrap().exists());

        let (_d, path) = fresh_path();
        let minted = load_or_bootstrap(&path).unwrap();
        assert_eq!(load_existing(&path).unwrap(), minted);
        fs::write(&path, "zz\n").unwrap();
        let msg = format!("{:#}", load_existing(&path).unwrap_err());
        assert!(msg.contains("corrupted"), "{msg}");
    }

    /// EVD-020: the mint goes through `atomic_file::replace`. What a crashed
    /// mint left at a temporary name — the old `agent_id.tmp` or a link at
    /// `.agent_id.tmp` — neither blocks the next mint (the old `create_new`
    /// on `agent_id.tmp` failed with EEXIST) nor is written through.
    #[test]
    fn leftovers_at_the_temporary_names_neither_block_nor_redirect_the_mint() {
        let (dir, path) = fresh_path();
        let victim = dir.path().join("audit.log");
        fs::write(&victim, "CHAIN").unwrap();
        fs::write(dir.path().join("agent_id.tmp"), "stale").unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join(".agent_id.tmp")).unwrap();
        let id = load_or_bootstrap(&path).expect("mint despite the leftovers");
        assert_eq!(fs::read_to_string(&victim).unwrap(), "CHAIN");
        let meta = fs::symlink_metadata(&path).unwrap();
        assert!(meta.file_type().is_file());
        assert_eq!(meta.permissions().mode() & 0o7777, FILE_MODE);
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!("{}\n", hex::encode(id))
        );
        assert!(!dir.path().join(".agent_id.tmp").exists());
    }

    /// MAIN-009: the agent reads its identity once and every consumer gets
    /// that value — no second read, no zero fallback in `main.rs`.
    #[test]
    fn the_agent_reads_its_identity_once() {
        let main = include_str!("main.rs");
        assert_eq!(main.matches("agent_id::resolve(").count(), 1);
        assert_eq!(main.matches("agent_id::load_or_bootstrap(").count(), 0);
        assert_eq!(main.matches("agent_id::load_existing(").count(), 0);
        assert!(!main.contains("[0u8; 16]"), "no zero fallback");
        // the overlay gate, the audit log and the admin plane take the one
        // binding
        assert!(main.contains("let agent_id = identity.id;"));
        let gate = main.find("OverlayGate::new(").expect("the overlay gate");
        assert!(
            main[gate..gate + 80].contains("agent_id,"),
            "the overlay gate takes the one binding"
        );
        for consumer in [
            "AuditLog::open(&cli.audit_log_file, key, agent_id)",
            "AdminAuth::load_with_agent_id(&cli.admin_pub, agent_id)",
        ] {
            assert!(main.contains(consumer), "{consumer}");
        }
        assert_eq!(main.matches("attest_identity(&identity)").count(), 2);
    }
}
