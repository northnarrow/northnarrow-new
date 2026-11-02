//! R14c (plan §3.3, Appendix B "Chiavi nominate solo in `nn-linux::keys`"):
//! the agent's keys are named in one place.
//!
//! The production sources of the core — the agent, nn-linux, nn-core,
//! nn-evidence — name the Ed25519 signing key type (`SigningKey`), the
//! vault's cipher and derivation (`Aes256Gcm`, `Hkdf`) and the readers and
//! makers of the key files (`read_signing_key`, `mint_signing_key`,
//! `load_or_init_master_key`) only in `crates/nn-linux/src/keys/`: every
//! other part of the agent holds a handle the key store gives (an
//! `AgentSigningKey` that signs, a `Vault` that seals and opens), never a
//! key. Test code aside: files of tests, modules declared under
//! `#[cfg(test)]`, a file's `#[cfg(test)]` module.
//!
//! Review of #482 (R14c-5, the reviewer's plantings P3, P4, P7, P8): also
//! the vault made for a path (`Vault::at`: a second reader of the master
//! key), the key's public half read from its file (`public_half`), the
//! key file's path (`DEFAULT_SIGNING_KEY_PATH`), and the crypto's own
//! types under any alias (`AesGcm`, `Aes256`, `Hmac`, `SecretKey`,
//! `ExpandedSecretKey`) — outside the store only where [`ALLOWED`] says,
//! that many times, and why.

mod support;

use std::fs;
use std::path::{Path, PathBuf};

use support::{production, repo_root, strip_comments};

const TREES: &[&str] = &[
    "agent/src",
    "crates/nn-linux/src",
    "crates/nn-core/src",
    "crates/nn-evidence/src",
];
const KEYS: &str = "crates/nn-linux/src/keys/";
const NAMES: &[&str] = &[
    "SigningKey",
    "Aes256Gcm",
    "Hkdf",
    "read_signing_key",
    "mint_signing_key",
    "load_or_init_master_key",
    "Locked::new",
    // review of #482 (R14c-5)
    "Vault::at",
    "public_half",
    "DEFAULT_SIGNING_KEY_PATH",
    "AesGcm",
    "Aes256",
    "Hmac",
    "SecretKey",
    "ExpandedSecretKey",
];

/// Review of #482 (R14c-5): the names used outside the store on purpose —
/// `(file, name, times, why)`; one more use anywhere fails.
const ALLOWED: &[(&str, &str, usize, &str)] = &[
    (
        "agent/src/lib.rs",
        "public_half",
        1,
        "the agent's `audit` shim re-exports it for the two readers below",
    ),
    (
        "agent/src/lib.rs",
        "DEFAULT_SIGNING_KEY_PATH",
        1,
        "the shim's re-export of the path (for the command line's default)",
    ),
    (
        "agent/src/config/overlay_floor.rs",
        "public_half",
        1,
        "the boot's rollback floor, read before the key store exists: the published half",
    ),
    (
        "agent/src/admin_host.rs",
        "public_half",
        1,
        "nn-admin's host verifies a chain in its own process, which has no key store",
    ),
    (
        "agent/src/boot/cli.rs",
        "DEFAULT_SIGNING_KEY_PATH",
        1,
        "the command line's default for --signing-key-file (a path, no read)",
    ),
];

fn rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    support::rs_files(dir, &mut out);
    out.sort();
    out
}

/// Every occurrence of `name` as a whole word (`AgentSigningKey` and
/// `VerifyingKey` are not `SigningKey`).
fn names(code: &str, name: &str) -> usize {
    code.match_indices(name)
        .filter(|(at, _)| {
            let before = code[..*at].chars().next_back();
            let after = code[at + name.len()..].chars().next();
            !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
                && !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
        })
        .count()
}

/// The files declared as `#[cfg(test)] mod x;` by their parent: test code.
fn test_modules(files: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for f in files {
        let text = fs::read_to_string(f).unwrap();
        let dir = if f
            .file_name()
            .is_some_and(|n| n == "mod.rs" || n == "lib.rs" || n == "main.rs")
        {
            f.parent().unwrap().to_path_buf()
        } else {
            f.with_extension("")
        };
        for (at, _) in text.match_indices("#[cfg(test)]\nmod ") {
            let rest = &text[at + "#[cfg(test)]\nmod ".len()..];
            if let Some(name) = rest.split(';').next() {
                if !name.contains(['{', '\n', ' ']) {
                    out.push(dir.join(format!("{name}.rs")));
                    out.push(dir.join(name).join("mod.rs"));
                }
            }
        }
    }
    out
}

#[test]
fn the_keys_are_named_in_one_place() {
    let mut files = Vec::new();
    for t in TREES {
        files.extend(rs_files(&repo_root().join(t)));
    }
    let tests = test_modules(&files);
    let mut bad = Vec::new();
    let mut in_keys = 0;
    for f in &files {
        let rel = f.strip_prefix(repo_root()).unwrap().display().to_string();
        let name = f.file_name().unwrap().to_string_lossy();
        if name == "tests.rs"
            || name.ends_with("_tests.rs")
            || rel.contains("/tests/")
            || tests.contains(f)
        {
            continue;
        }
        let code = strip_comments(&fs::read_to_string(f).unwrap());
        let code = production(&code);
        for n in NAMES {
            let k = names(&code, n);
            let allowed = ALLOWED
                .iter()
                .find(|(f, name, _, _)| *f == rel && name == n)
                .map_or(0, |a| a.2);
            if rel.starts_with(KEYS) {
                in_keys += k;
            } else if k != allowed {
                bad.push(format!(
                    "{rel}: names `{n}` {k} time(s) (allowed: {allowed})"
                ));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "a key named outside nn-linux::keys:\n{}",
        bad.join("\n")
    );
    assert!(in_keys >= 10, "the key store names them: {in_keys}");
}

#[test]
fn the_key_store_is_not_clone_and_hands_out_handles() {
    let keys = fs::read_to_string(repo_root().join("crates/nn-linux/src/keys/mod.rs")).unwrap();
    let code = strip_comments(&keys);
    let at = code.find("pub struct KeyStore {").expect("the key store");
    let before = &code[..at];
    let derive = before
        .rfind("#[derive(")
        .map(|d| &before[d..])
        .unwrap_or("");
    assert!(!derive.contains("Clone"), "KeyStore is not Clone: {derive}");
    // the signing key's handle shares the one key; no method gives bytes
    assert!(code.contains("inner: Arc<Locked<SigningKey>>,"));
    for leak in [
        "fn to_bytes(",
        "fn secret(",
        "fn as_bytes(",
        "fn key_bytes(",
    ] {
        assert!(
            !production(&code).contains(leak),
            "a method that gives the key: {leak}"
        );
    }
    let vault = strip_comments(
        &fs::read_to_string(repo_root().join("crates/nn-linux/src/keys/vault.rs")).unwrap(),
    );
    assert!(vault.contains("type MasterKey = Arc<Locked<Zeroizing<[u8; 32]>>>;"));
    assert!(vault.contains("key: parking_lot::Mutex<Option<MasterKey>>,"));
}

#[test]
fn a_planted_key_outside_the_store_is_found() {
    let planted = "fn f() { let k = ed25519_dalek::SigningKey::from_bytes(&[0; 32]); }";
    assert_eq!(
        names(&production(&strip_comments(planted)), "SigningKey"),
        1
    );
    // review of #482: the reviewer's P3, P4, P7, P8
    for (planted, name) in [
        (
            "fn f() { let k = std::fs::read_to_string(DEFAULT_SIGNING_KEY_PATH); }",
            "DEFAULT_SIGNING_KEY_PATH",
        ),
        (
            "fn f(p: &Path) { let v = crate::keys::public_half(p); }",
            "public_half",
        ),
        (
            "type C = aes_gcm::AesGcm<aes_gcm::aes::Aes256, U12>;",
            "AesGcm",
        ),
        ("type C = aes_gcm::AesGcm<aes_gcm::aes::Aes256, U12>;", "Aes256"),
        (
            "fn f() { let v = crate::keys::Vault::at(Path::new(\"/etc/northnarrow/master.key\")); }",
            "Vault::at",
        ),
        ("fn f() { let m = hmac::Hmac::<sha2::Sha256>::new_from_slice(k); }", "Hmac"),
    ] {
        assert_eq!(names(&production(&strip_comments(planted)), name), 1, "{planted}");
    }
    assert_eq!(names("Aes256Gcm", "Aes256"), 0);
    assert_eq!(names("ExpandedSecretKey", "SecretKey"), 0);
    assert_eq!(names("AgentSigningKey VerifyingKey", "SigningKey"), 0);
    let tested = format!("fn g() {{}}\n#[cfg(test)]\nmod tests {{\n{planted}\n}}\n");
    assert_eq!(
        names(&production(&strip_comments(&tested)), "SigningKey"),
        0
    );
}
