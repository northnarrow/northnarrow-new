//! The install manifest's check reached through the fuzz target's
//! fixture (external audit WDG-R05). Wave 4 restructure, R09c (lab PR
//! 257): cut verbatim from the tests of `install_manifest`, which leaves
//! for nn-linux; the fixture is the agent's `fuzz_api` (the fuzz targets'
//! wrappers, until R17), so the test stays with it, with a copy of the
//! manifest helper it builds the fixture's manifest with.

use std::path::Path;

use crate::install_manifest::{sha256_file, IntegrityOutcome};

/// The manifest `install.sh` writes, with these hashes (a copy of the
/// helper of `install_manifest`'s tests).
fn manifest_json(bin_dir: &Path, agent: &str, wd: &str, admin: &str, ebpf: &str) -> String {
    format!(
        r#"{{"version":"0.0.1","installed_at":"2026-10-10T00:00:00Z","provenance":"attested",
                "bin_dir":"{}","files":{{"northnarrow-agent":"{agent}","northnarrow-watchdog":"{wd}",
                "nn-admin":"{admin}","ebpf_object":"{ebpf}"}},"tarball_sha256":"ab"}}"#,
        bin_dir.display()
    )
}

/// External audit WDG-R05 (NN-AUD-371): the fuzz target's fixture (a
/// fixed `bin_dir` holding a binary for each recorded file name,
/// `fuzz_api`) reaches the hash comparison. Through `/proc/self/exe`
/// every input ended `NotApplicable`, before any hash.
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
