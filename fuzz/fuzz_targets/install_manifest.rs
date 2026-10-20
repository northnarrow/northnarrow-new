#![no_main]
//! The install manifest is parsed at every boot and decides whether the
//! agent starts. The check runs against a fixed fixture directory (the
//! agent and the other two binaries, `fuzz_api`), so every manifest that
//! parses reaches the hash comparison (WDG-R05: through `/proc/self/exe`
//! every input ended `NotApplicable`). Beyond "never panics":
//! - the outcome is a verdict on the fixture: never `NoManifest` or
//!   `NotApplicable`;
//! - `Verified` exactly when every recorded name is one of the four
//!   install.sh writes and its hash is the fixture's; every other entry is
//!   a mismatch, an unknown name refused without being opened (an
//!   absolute name such as `/dev/zero` hung the check).
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use northnarrow_agent::fuzz_api::{
    install_manifest_check_in_dir, write_install_manifest_fixture,
    INSTALL_MANIFEST_FIXTURE_EBPF_SHA,
};
use northnarrow_agent::install_manifest::{
    sha256_file, IntegrityOutcome, EBPF_OBJECT_KEY, RECORDED_NAMES, UNKNOWN_NAME,
};

mod scratch;

/// The fixture directory and the hash of each recorded name in it.
fn fixture() -> &'static (&'static Path, BTreeMap<&'static str, String>) {
    static FIXTURE: OnceLock<(&'static Path, BTreeMap<&'static str, String>)> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let dir = scratch::dir("nn-fuzz-manifest-");
        write_install_manifest_fixture(dir).expect("the fixture binaries");
        let mut hashes = BTreeMap::new();
        for name in RECORDED_NAMES {
            let h = if name == EBPF_OBJECT_KEY {
                INSTALL_MANIFEST_FIXTURE_EBPF_SHA.to_string()
            } else {
                sha256_file(&dir.join(name)).expect("a fixture binary")
            };
            hashes.insert(name, h);
        }
        (dir, hashes)
    })
}

fuzz_target!(|data: &[u8]| {
    let (dir, hashes) = fixture();
    let (manifest, outcome) =
        install_manifest_check_in_dir(data, dir, INSTALL_MANIFEST_FIXTURE_EBPF_SHA);
    let Some(manifest) = manifest else {
        assert!(
            matches!(outcome, IntegrityOutcome::Unreadable { .. }),
            "{outcome:?}"
        );
        return;
    };
    // what the fixture says of each entry: matches, or why not
    let mut want: BTreeMap<&str, Option<&str>> = BTreeMap::new();
    for (name, expected) in &manifest.files {
        let verdict = match hashes.get(name.as_str()) {
            None => Some(UNKNOWN_NAME),
            Some(h) if *h == expected.trim().to_ascii_lowercase() => None,
            Some(_) => Some("hash"),
        };
        want.insert(name, verdict);
    }
    match outcome {
        IntegrityOutcome::Verified { checked, .. } => {
            assert!(want.values().all(Option::is_none), "verified: {want:?}");
            assert_eq!(checked, manifest.files.len());
        }
        IntegrityOutcome::Mismatch { mismatches, .. } => {
            let got: BTreeMap<&str, &str> = mismatches
                .iter()
                .map(|m| (m.name.as_str(), m.actual.as_str()))
                .collect();
            assert_eq!(got.len(), mismatches.len(), "a name reported twice");
            for (name, verdict) in &want {
                match verdict {
                    None => assert!(!got.contains_key(name), "{name}: matched, reported"),
                    Some(UNKNOWN_NAME) => assert_eq!(got.get(name), Some(&UNKNOWN_NAME), "{name}"),
                    Some(_) => {
                        let actual = got
                            .get(name)
                            .unwrap_or_else(|| panic!("{name}: unreported"));
                        assert_ne!(*actual, UNKNOWN_NAME, "{name}: a recorded name refused");
                    }
                }
            }
        }
        other => panic!("not a verdict on the fixture: {other:?}"),
    }
});
