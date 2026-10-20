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
//! [`ALLOW_UNVERIFIED_ENV`] is set. `install.sh` writes the manifest on
//! every install, source trees included, so a missing one is fatal too
//! once the signed audit chain holds a boot that verified against it
//! (external audit DEP-009, [`BootHistory`]); before that (a developer run,
//! an install older than the manifest) it is reported, not punished.

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
/// The names `install.sh` records in the `files` map, the only ones
/// compared (external audit WDG-R05, NN-AUD-371).
pub const RECORDED_NAMES: [&str; 4] = [
    "northnarrow-agent",
    "northnarrow-watchdog",
    "nn-admin",
    EBPF_OBJECT_KEY,
];
/// [`Mismatch::actual`] of a name outside [`RECORDED_NAMES`]: refused, not
/// hashed.
pub const UNKNOWN_NAME: &str = "refused: not a recorded binary name";

/// `install-manifest.json` as written by `install.sh`.
#[derive(Debug, Clone, Deserialize)]
pub struct InstallManifest {
    pub version: String,
    #[serde(default)]
    pub installed_at: String,
    /// `attested` | `checksums` | `manifest` | `source-tree` | `unverified`
    /// | `package`.
    pub provenance: String,
    /// External audit DEP-007: the `install.sh` flag that accepted a level
    /// below `attested` (lab PR 220: `--allow-unverified`, its former name
    /// `--allow-manifest-only`, `--source-tree`, `--no-verify`); absent when
    /// none was needed.
    #[serde(default)]
    pub verify_override: Option<String>,
    /// Lab follow-up (lab PR 165): the `install.sh` flags that accepted a
    /// host without one of the agent's prerequisites (`--without-nftables`);
    /// empty when none was needed, and in manifests written before it.
    #[serde(default)]
    pub prerequisite_overrides: Vec<String>,
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
    /// No manifest at the path: a binary not installed by `install.sh` (a
    /// developer run), an install older than this check — or a manifest
    /// that was removed ([`BootHistory`] tells them apart).
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
    /// External audit DEP-009: so is a missing one, unless the audit chain
    /// shows this install never had a verified boot — deleting the file
    /// used to switch the whole check off, where editing it refused the
    /// boot.
    pub fn is_fatal(&self, allow_env: Option<&str>, history: BootHistory) -> bool {
        let allowed = allow_env == Some("1");
        match self {
            IntegrityOutcome::Mismatch { .. } | IntegrityOutcome::Unreadable { .. } => !allowed,
            IntegrityOutcome::NoManifest { .. } => {
                history != BootHistory::NeverVerified && !allowed
            }
            _ => false,
        }
    }
}

/// External audit DEP-009: what the signed audit chain says about the
/// earlier boots of this install — the sentinel that tells a manifest that
/// never existed from one that was removed. Read only when the manifest is
/// missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootHistory {
    /// No earlier `agent_boot` verified the binaries against a manifest:
    /// a fresh chain, a developer run, an install older than the manifest.
    NeverVerified,
    /// An earlier `agent_boot` recorded `binary_integrity = verified`: the
    /// manifest existed, so its absence now means it was removed.
    VerifiedBefore,
    /// The chain could not be read: nothing shows the manifest never
    /// existed, so its absence counts as a removal.
    Unknown,
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
    let manifest = match parse_manifest(&text) {
        Ok(m) => m,
        Err(reason) => {
            return IntegrityOutcome::Unreadable {
                path: manifest_path.to_path_buf(),
                reason,
            }
        }
    };
    check_with(&manifest, own_exe, ebpf_object_sha)
}

/// Parse a manifest's text, as [`check`] does (the reason of an
/// [`IntegrityOutcome::Unreadable`] on failure).
pub fn parse_manifest(text: &str) -> Result<InstallManifest, String> {
    serde_json::from_str(text).map_err(|e| format!("parse: {e}"))
}

/// [`check`] on an already-parsed manifest.
pub fn check_with(
    manifest: &InstallManifest,
    own_exe: &Path,
    ebpf_object_sha: &str,
) -> IntegrityOutcome {
    // Only the installed agent itself is compared: a copy with another
    // name — even inside bin_dir, like the e2e fixtures'
    // `northnarrow-agent-e2etest-<ts>-<pid>` — describes a different
    // build and must not be judged by this manifest.
    let bin_dir = Path::new(&manifest.bin_dir);
    let bin_dir_canon = bin_dir
        .canonicalize()
        .unwrap_or_else(|_| bin_dir.to_path_buf());
    let installed_agent = bin_dir_canon.join("northnarrow-agent");
    let own_canon = own_exe
        .canonicalize()
        .unwrap_or_else(|_| own_exe.to_path_buf());
    if own_canon != installed_agent {
        return IntegrityOutcome::NotApplicable {
            own_exe: own_exe.to_path_buf(),
            bin_dir: manifest.bin_dir.clone(),
        };
    }
    let mut mismatches = Vec::new();
    let mut checked = 0usize;
    for (name, expected) in &manifest.files {
        let expected = expected.trim().to_ascii_lowercase();
        // External audit WDG-R05 (NN-AUD-371): only the names install.sh
        // records. Any other key was hashed as `bin_dir.join(name)`, and a
        // join with an absolute name drops `bin_dir`: `/dev/zero` hung the
        // boot check, `../` reached any file. Refused, never opened.
        if !RECORDED_NAMES.contains(&name.as_str()) {
            mismatches.push(Mismatch {
                name: name.clone(),
                expected,
                actual: UNKNOWN_NAME.to_string(),
            });
            continue;
        }
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
        assert!(!out.is_fatal(None, BootHistory::VerifiedBefore));
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
        assert!(out.is_fatal(None, BootHistory::NeverVerified));
        assert!(out.is_fatal(Some("0"), BootHistory::NeverVerified));
        assert!(!out.is_fatal(Some("1"), BootHistory::NeverVerified));
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
        assert!(!out.is_fatal(None, BootHistory::VerifiedBefore));
        assert_eq!(out.label(), "not-applicable");
        // same directory, different name (an e2e fixture copy): not compared either
        let fixture = write(dir.path(), "northnarrow-agent-e2etest-1-2", b"fixture");
        let out = check(&mp, &fixture, "33");
        assert!(
            matches!(out, IntegrityOutcome::NotApplicable { .. }),
            "{out:?}"
        );
    }

    /// External audit DEP-009: a binary that never ran against a manifest
    /// (a developer run, an install older than the manifest) still boots.
    #[test]
    fn missing_manifest_on_fresh_chain_is_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let out = check(&dir.path().join("nope.json"), Path::new("/bin/true"), "x");
        assert!(matches!(out, IntegrityOutcome::NoManifest { .. }));
        assert!(!out.is_fatal(None, BootHistory::NeverVerified));
        assert_eq!(out.provenance(), "none");
        assert_eq!(out.label(), "no-manifest");
    }

    /// External audit DEP-009: once a boot verified against the manifest,
    /// its absence is a removal — refused like an unreadable one, with the
    /// same development override. A chain that cannot be read proves
    /// nothing either way and refuses too.
    #[test]
    fn missing_manifest_after_verified_boot_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let out = check(&dir.path().join("nope.json"), Path::new("/bin/true"), "x");
        assert!(matches!(out, IntegrityOutcome::NoManifest { .. }));
        assert!(out.is_fatal(None, BootHistory::VerifiedBefore));
        assert!(out.is_fatal(Some("0"), BootHistory::VerifiedBefore));
        assert!(!out.is_fatal(Some("1"), BootHistory::VerifiedBefore));
        assert!(out.is_fatal(None, BootHistory::Unknown));
        assert!(!out.is_fatal(Some("1"), BootHistory::Unknown));
    }

    /// External audit DEP-007: the flag that accepted a weaker level is
    /// read back; manifests written before it have none.
    #[test]
    fn verify_override_is_optional() {
        let dir = tempfile::tempdir().unwrap();
        let m = manifest_json(dir.path(), "00", "11", "22", "33");
        let parsed: InstallManifest = serde_json::from_str(&m).unwrap();
        assert_eq!(parsed.verify_override, None);
        let with = m.replacen(
            r#""provenance":"attested","#,
            r#""provenance":"source-tree","verify_override":"--source-tree","#,
            1,
        );
        let parsed: InstallManifest = serde_json::from_str(&with).unwrap();
        assert_eq!(parsed.provenance, "source-tree");
        assert_eq!(parsed.verify_override.as_deref(), Some("--source-tree"));
    }

    /// Lab follow-up (lab PR 165): the flag that accepted a host without
    /// `nft` is read back; manifests written before it have none.
    #[test]
    fn prerequisite_overrides_are_optional() {
        let dir = tempfile::tempdir().unwrap();
        let m = manifest_json(dir.path(), "00", "11", "22", "33");
        let parsed: InstallManifest = serde_json::from_str(&m).unwrap();
        assert!(parsed.prerequisite_overrides.is_empty());
        let with = m.replacen(
            r#""provenance":"attested","#,
            r#""provenance":"attested","prerequisite_overrides":["--without-nftables"],"#,
            1,
        );
        let parsed: InstallManifest = serde_json::from_str(&with).unwrap();
        assert_eq!(parsed.prerequisite_overrides, vec!["--without-nftables"]);
        let empty = m.replacen(
            r#""provenance":"attested","#,
            r#""provenance":"attested","prerequisite_overrides":[],"#,
            1,
        );
        let parsed: InstallManifest = serde_json::from_str(&empty).unwrap();
        assert!(parsed.prerequisite_overrides.is_empty());
    }

    /// External audit WDG-R05 (NN-AUD-371): a name outside the four
    /// install.sh records is a mismatch and is never opened — not an
    /// absolute path (a join drops `bin_dir`), not a relative one that
    /// leaves it or names a recorded binary another way. Before the check,
    /// each of these files was hashed and, its hash recorded, verified
    /// (`/dev/zero`, which hung the check, is the fuzz regression input
    /// `fuzz/regressions/install_manifest/absolute-dev-zero.json`).
    #[test]
    fn unknown_or_absolute_names_are_a_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let agent = write(dir.path(), "northnarrow-agent", b"agent-bytes");
        let secret = write(outside.path(), "secret", b"not a binary");
        let agent_sha = sha256_file(&agent).unwrap();
        let secret_sha = sha256_file(&secret).unwrap();
        let rel = format!(
            "../{}/secret",
            outside.path().file_name().unwrap().to_str().unwrap()
        );
        for (name, sha) in [
            (secret.display().to_string(), &secret_sha),
            (rel, &secret_sha),
            ("./northnarrow-agent".to_string(), &agent_sha),
        ] {
            let m = format!(
                r#"{{"version":"0.0.1","provenance":"attested","bin_dir":"{}",
                    "files":{{"northnarrow-agent":"{agent_sha}","{name}":"{sha}"}}}}"#,
                dir.path().display()
            );
            let mp = write(dir.path(), "install-manifest.json", m.as_bytes());
            match check(&mp, &agent, "x") {
                IntegrityOutcome::Mismatch { mismatches, .. } => {
                    assert_eq!(mismatches.len(), 1, "{name}: {mismatches:?}");
                    assert_eq!(mismatches[0].name, name);
                    assert_eq!(mismatches[0].actual, UNKNOWN_NAME);
                }
                other => panic!("{name}: expected Mismatch, got {other:?}"),
            }
        }
    }

    /// External audit WDG-R05 (NN-AUD-371): the fuzz target's fixture (a
    /// fixed `bin_dir` holding the three binaries, `fuzz_api`) reaches the
    /// hash comparison. Through `/proc/self/exe` every input ended
    /// `NotApplicable`, before any hash.
    #[test]
    fn fuzz_fixture_reaches_hash_comparison() {
        use crate::fuzz_api::{
            install_manifest_check_in_dir, write_install_manifest_fixture,
            INSTALL_MANIFEST_FIXTURE_EBPF_SHA,
        };
        let dir = tempfile::tempdir().unwrap();
        write_install_manifest_fixture(dir.path()).unwrap();
        let sha = |n: &str| sha256_file(&dir.path().join(n)).unwrap();
        let good = manifest_json(
            Path::new("/somewhere/else"),
            &sha("northnarrow-agent"),
            &sha("northnarrow-watchdog"),
            &sha("nn-admin"),
            INSTALL_MANIFEST_FIXTURE_EBPF_SHA,
        );
        let (parsed, out) = install_manifest_check_in_dir(
            good.as_bytes(),
            dir.path(),
            INSTALL_MANIFEST_FIXTURE_EBPF_SHA,
        );
        assert!(parsed.is_some());
        assert!(
            matches!(out, IntegrityOutcome::Verified { checked: 4, .. }),
            "{out:?}"
        );
        let bad = good.replacen(&sha("nn-admin"), &"0".repeat(64), 1);
        let (_, out) = install_manifest_check_in_dir(
            bad.as_bytes(),
            dir.path(),
            INSTALL_MANIFEST_FIXTURE_EBPF_SHA,
        );
        assert!(matches!(out, IntegrityOutcome::Mismatch { .. }), "{out:?}");
        let (parsed, out) = install_manifest_check_in_dir(b"{not json", dir.path(), "x");
        assert!(parsed.is_none());
        assert!(
            matches!(out, IntegrityOutcome::Unreadable { .. }),
            "{out:?}"
        );
    }

    #[test]
    fn unparseable_manifest_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let mp = write(dir.path(), "install-manifest.json", b"{not json");
        let out = check(&mp, Path::new("/bin/true"), "x");
        assert!(matches!(out, IntegrityOutcome::Unreadable { .. }));
        assert!(out.is_fatal(None, BootHistory::NeverVerified));
        assert!(!out.is_fatal(Some("1"), BootHistory::NeverVerified));
    }
}
