//! Boot-time self-verification against the install manifest.
//!
//! `deploy/install.sh` verifies the release (tree manifest, `SHA256SUMS`,
//! SLSA attestation when a verifier is available) and then records what
//! it installed in `/etc/northnarrow/install-manifest.json`: the
//! provenance level it could establish and the SHA-256 of every binary
//! and of the eBPF object. That file lives under the anti-tamper
//! `inode_protect` hook like the rest of `/etc/northnarrow`.
//!
//! At every boot the agent closes the loop: it hashes its own executable
//! (`/proc/self/exe`), the watchdog and `nn-admin` under the recorded
//! `bin_dir`, and compares the embedded eBPF object hash with the
//! manifest. Provenance verified at deploy time is worth little if the
//! binary that runs a month later is not the one that was verified —
//! this is the "binding runtime" half of the supply chain (ROADMAP,
//! Tappa 10.8). A mismatch is fatal in enforcement mode unless
//! [`ALLOW_UNVERIFIED_ENV`] is set; a missing manifest (a source-tree
//! install, the lab) is reported, not punished.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Where `install.sh` writes the manifest.
pub const DEFAULT_INSTALL_MANIFEST_PATH: &str = "/etc/northnarrow/install-manifest.json";
/// Set to `1` to turn a binary mismatch from fatal into a WARN (a
/// deliberate dev override, never a default).
pub const ALLOW_UNVERIFIED_ENV: &str = "NN_ALLOW_UNVERIFIED_BINARY";
/// Manifest key of the eBPF object hash (`files` map).
pub const EBPF_OBJECT_KEY: &str = "ebpf_object";

/// `install-manifest.json` as written by `install.sh`.
#[derive(Debug, Clone, Deserialize)]
pub struct InstallManifest {
    pub version: String,
    #[serde(default)]
    pub installed_at: String,
    /// `attested` | `checksums` | `manifest` | `source-tree` | `unverified`.
    pub provenance: String,
    /// Directory the binaries were installed into.
    pub bin_dir: String,
    /// `name → sha256 hex`. Names: `northnarrow-agent`, `northnarrow-watchdog`,
    /// `nn-admin`, [`EBPF_OBJECT_KEY`].
    pub files: BTreeMap<String, String>,
    #[serde(default)]
    pub tarball_sha256: Option<String>,
    #[serde(default)]
    pub attestation: Option<serde_json::Value>,
}

/// One file that did not match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    pub name: String,
    pub expected: String,
    /// Hash actually observed, or `missing` / an error text.
    pub actual: String,
}

/// Result of the boot-time check.
#[derive(Debug, Clone)]
pub enum IntegrityOutcome {
    /// No manifest at the path: a source-tree install (the lab) or an
    /// installer older than this check.
    NoManifest { path: PathBuf },
    /// A manifest exists but this binary does not run from its `bin_dir`
    /// (a test fixture, a developer build started by hand): the recorded
    /// hashes describe another copy, so nothing is compared.
    NotApplicable { own_exe: PathBuf, bin_dir: String },
    /// The manifest exists but could not be read or parsed.
    Unreadable { path: PathBuf, reason: String },
    /// Every recorded file matches.
    Verified { provenance: String, checked: usize },
    /// At least one recorded file differs from what runs.
    Mismatch {
        provenance: String,
        mismatches: Vec<Mismatch>,
    },
}

impl IntegrityOutcome {
    /// Short label for the audit `agent_boot` entry.
    pub fn label(&self) -> &'static str {
        match self {
            IntegrityOutcome::NoManifest { .. } => "no-manifest",
            IntegrityOutcome::NotApplicable { .. } => "not-applicable",
            IntegrityOutcome::Unreadable { .. } => "unreadable",
            IntegrityOutcome::Verified { .. } => "verified",
            IntegrityOutcome::Mismatch { .. } => "mismatch",
        }
    }

    /// Provenance level recorded by the installer (`none` when unknown).
    pub fn provenance(&self) -> &str {
        match self {
            IntegrityOutcome::Verified { provenance, .. }
            | IntegrityOutcome::Mismatch { provenance, .. } => provenance,
            _ => "none",
        }
    }

    /// A mismatch is fatal unless the operator set [`ALLOW_UNVERIFIED_ENV`]
    /// to `1`. An unreadable manifest is fatal too: under `inode_protect`
    /// it cannot be corrupted by accident, so a broken one is a signal.
    pub fn is_fatal(&self, allow_env: Option<&str>) -> bool {
        let allowed = allow_env == Some("1");
        match self {
            IntegrityOutcome::Mismatch { .. } | IntegrityOutcome::Unreadable { .. } => !allowed,
            _ => false,
        }
    }
}

/// Hash a file with SHA-256 (hex, lowercase) in 64 KiB chunks.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Run the check against the manifest at `manifest_path`: `own_exe` is
/// the running agent binary, `ebpf_object_sha` the hash embedded at
/// build time (`NN_EBPF_OBJECT_SHA`).
pub fn check(manifest_path: &Path, own_exe: &Path, ebpf_object_sha: &str) -> IntegrityOutcome {
    let text = match std::fs::read_to_string(manifest_path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return IntegrityOutcome::NoManifest {
                path: manifest_path.to_path_buf(),
            }
        }
        Err(e) => {
            return IntegrityOutcome::Unreadable {
                path: manifest_path.to_path_buf(),
                reason: e.to_string(),
            }
        }
    };
    let manifest: InstallManifest = match serde_json::from_str(&text) {
        Ok(m) => m,
        Err(e) => {
            return IntegrityOutcome::Unreadable {
                path: manifest_path.to_path_buf(),
                reason: format!("parse: {e}"),
            }
        }
    };
    check_with(&manifest, own_exe, ebpf_object_sha)
}

/// [`check`] on an already-parsed manifest.
pub fn check_with(
    manifest: &InstallManifest,
    own_exe: &Path,
    ebpf_object_sha: &str,
) -> IntegrityOutcome {
    let bin_dir = Path::new(&manifest.bin_dir);
    let own_dir = own_exe
        .canonicalize()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));
    let bin_dir_canon = bin_dir
        .canonicalize()
        .unwrap_or_else(|_| bin_dir.to_path_buf());
    if own_dir.as_deref() != Some(bin_dir_canon.as_path()) {
        return IntegrityOutcome::NotApplicable {
            own_exe: own_exe.to_path_buf(),
            bin_dir: manifest.bin_dir.clone(),
        };
    }
    let mut mismatches = Vec::new();
    let mut checked = 0usize;
    for (name, expected) in &manifest.files {
        let expected = expected.trim().to_ascii_lowercase();
        let actual = if name == EBPF_OBJECT_KEY {
            ebpf_object_sha.trim().to_ascii_lowercase()
        } else {
            let path = if name == "northnarrow-agent" {
                own_exe.to_path_buf()
            } else {
                bin_dir.join(name)
            };
            match sha256_file(&path) {
                Ok(h) => h,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => "missing".to_string(),
                Err(e) => format!("error: {e}"),
            }
        };
        checked += 1;
        if actual != expected {
            mismatches.push(Mismatch {
                name: name.clone(),
                expected,
                actual,
            });
        }
    }
    if mismatches.is_empty() {
        IntegrityOutcome::Verified {
            provenance: manifest.provenance.clone(),
            checked,
        }
    } else {
        IntegrityOutcome::Mismatch {
            provenance: manifest.provenance.clone(),
            mismatches,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    fn manifest_json(bin_dir: &Path, agent: &str, wd: &str, admin: &str, ebpf: &str) -> String {
        format!(
            r#"{{"version":"0.0.1","installed_at":"2026-10-10T00:00:00Z","provenance":"attested",
                "bin_dir":"{}","files":{{"northnarrow-agent":"{agent}","northnarrow-watchdog":"{wd}",
                "nn-admin":"{admin}","ebpf_object":"{ebpf}"}},"tarball_sha256":"ab"}}"#,
            bin_dir.display()
        )
    }

    #[test]
    fn verified_when_every_hash_matches() {
        let dir = tempfile::tempdir().unwrap();
        let agent = write(dir.path(), "northnarrow-agent", b"agent-bytes");
        write(dir.path(), "northnarrow-watchdog", b"wd-bytes");
        write(dir.path(), "nn-admin", b"admin-bytes");
        let m = manifest_json(
            dir.path(),
            &sha256_file(&agent).unwrap(),
            &sha256_file(&dir.path().join("northnarrow-watchdog")).unwrap(),
            &sha256_file(&dir.path().join("nn-admin")).unwrap(),
            "EBPFSHA",
        );
        let mp = write(dir.path(), "install-manifest.json", m.as_bytes());
        let out = check(&mp, &agent, "ebpfsha");
        match &out {
            IntegrityOutcome::Verified {
                provenance,
                checked,
            } => {
                assert_eq!(provenance, "attested");
                assert_eq!(*checked, 4);
            }
            other => panic!("expected Verified, got {other:?}"),
        }
        assert!(!out.is_fatal(None));
        assert_eq!(out.label(), "verified");
    }

    #[test]
    fn mismatch_names_the_file_and_is_fatal_unless_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let agent = write(dir.path(), "northnarrow-agent", b"agent-bytes");
        write(dir.path(), "northnarrow-watchdog", b"wd-bytes");
        // nn-admin deliberately absent
        let m = manifest_json(
            dir.path(),
            &sha256_file(&agent).unwrap(),
            "0000",
            "1111",
            "ebpfsha",
        );
        let mp = write(dir.path(), "install-manifest.json", m.as_bytes());
        let out = check(&mp, &agent, "ebpfsha");
        match &out {
            IntegrityOutcome::Mismatch { mismatches, .. } => {
                let names: Vec<&str> = mismatches.iter().map(|m| m.name.as_str()).collect();
                assert_eq!(names, vec!["nn-admin", "northnarrow-watchdog"]);
                assert_eq!(mismatches[0].actual, "missing");
            }
            other => panic!("expected Mismatch, got {other:?}"),
        }
        assert!(out.is_fatal(None));
        assert!(out.is_fatal(Some("0")));
        assert!(!out.is_fatal(Some("1")));
        assert_eq!(out.label(), "mismatch");
    }

    #[test]
    fn binary_outside_bin_dir_is_not_applicable() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let agent = write(other.path(), "northnarrow-agent", b"test-fixture-copy");
        write(dir.path(), "northnarrow-agent", b"installed");
        let m = manifest_json(dir.path(), "00", "11", "22", "33");
        let mp = write(dir.path(), "install-manifest.json", m.as_bytes());
        let out = check(&mp, &agent, "33");
        assert!(
            matches!(out, IntegrityOutcome::NotApplicable { .. }),
            "{out:?}"
        );
        assert!(!out.is_fatal(None));
        assert_eq!(out.label(), "not-applicable");
    }

    #[test]
    fn missing_manifest_is_reported_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let out = check(&dir.path().join("nope.json"), Path::new("/bin/true"), "x");
        assert!(matches!(out, IntegrityOutcome::NoManifest { .. }));
        assert!(!out.is_fatal(None));
        assert_eq!(out.provenance(), "none");
    }

    #[test]
    fn unparseable_manifest_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let mp = write(dir.path(), "install-manifest.json", b"{not json");
        let out = check(&mp, Path::new("/bin/true"), "x");
        assert!(matches!(out, IntegrityOutcome::Unreadable { .. }));
        assert!(out.is_fatal(None));
        assert!(!out.is_fatal(Some("1")));
    }
}
