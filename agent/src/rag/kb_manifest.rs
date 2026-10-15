//! The pinned knowledge-base manifest (external audit XAI-001, XAI-009).
//!
//! `cargo xtask rag-kb` writes `docs/kb-sources/kb_index.json`: for each
//! source, the dump's file name and the SHA-256 of its bytes. The agent
//! embeds that file at build time, so the manifest is as trustworthy as
//! the binary (which the install manifest already checks), and the RAG
//! corpus is opened only when the dump directory holds exactly the listed
//! dumps, byte for byte. A `*.jsonl` the manifest does not list, a dump
//! that is missing, and a dump whose digest differs are refusals: the
//! canary then runs without RAG ([`super::canary`]). A KB update needs an
//! agent release, as the pinned anchor already implied.
//!
//! The dumps are read once into memory, hashed, and parsed from those same
//! bytes, so what is verified is what is indexed.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// `docs/kb-sources/kb_index.json` as built into this binary.
pub const PINNED_KB_INDEX: &str = include_str!("../../../docs/kb-sources/kb_index.json");

/// The manifest domain `xtask/src/rag_kb.rs` writes (`KB_CANON_DOMAIN`).
const KB_DOMAIN: &str = "NN-RAG-KB-CANON-v1";

/// Upper bound on one dump (the ATT&CK v18.1 dump is about 2 MB): a
/// planted multi-gigabyte file is refused before it is read into memory.
pub const MAX_DUMP_BYTES: u64 = 64 * 1024 * 1024;

/// Why the corpus was not opened.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KbRefusal {
    /// The dump directory cannot be listed, or a pinned dump is absent.
    #[error("canonical corpus missing in {dir}: {detail}")]
    Missing { dir: PathBuf, detail: String },
    /// A `*.jsonl` in the dump directory that the manifest does not list.
    #[error("unlisted dump {file} in {dir}")]
    Unlisted { dir: PathBuf, file: String },
    /// A pinned dump whose bytes differ from the manifest.
    #[error("dump {file} does not match the pinned digest (expected {expected}, found {actual})")]
    Mismatch {
        file: String,
        expected: String,
        actual: String,
    },
    /// A pinned dump that is present but cannot be read as a regular file
    /// of at most [`MAX_DUMP_BYTES`].
    #[error("dump {file} unreadable: {detail}")]
    Unreadable { file: String, detail: String },
    /// The manifest itself is malformed (a build defect for the pinned one).
    #[error("knowledge-base manifest invalid: {0}")]
    BadManifest(String),
}

impl KbRefusal {
    /// `true` when the corpus is absent (rather than altered): the canary
    /// words its log line accordingly.
    pub fn is_missing(&self) -> bool {
        matches!(self, Self::Missing { .. })
    }
}

/// The dump names and digests the corpus must match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KbManifest {
    kb_index_hash: String,
    /// Dump file name → lower-case hex SHA-256 of its bytes.
    dumps: BTreeMap<String, String>,
}

#[derive(serde::Deserialize)]
struct RawManifest {
    domain: String,
    kb_index_hash: String,
    sources: Vec<RawSource>,
}

#[derive(serde::Deserialize)]
struct RawSource {
    canonical_dump_sha256: String,
    file: String,
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A bare `*.jsonl` file name: no directory part, no hidden or dot name.
fn is_dump_name(s: &str) -> bool {
    s.len() > ".jsonl".len()
        && s.ends_with(".jsonl")
        && !s.starts_with('.')
        && !s.contains('/')
        && !s.contains('\0')
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

impl KbManifest {
    /// The manifest built into this binary.
    pub fn pinned() -> Result<Self, KbRefusal> {
        Self::parse(PINNED_KB_INDEX)
    }

    /// Parse a `kb_index.json`. Every source must name its dump file and
    /// a 64-character lower-case SHA-256; names are unique.
    pub fn parse(json: &str) -> Result<Self, KbRefusal> {
        let raw: RawManifest =
            serde_json::from_str(json).map_err(|e| KbRefusal::BadManifest(e.to_string()))?;
        if raw.domain != KB_DOMAIN {
            return Err(KbRefusal::BadManifest(format!(
                "domain {:?}, expected {KB_DOMAIN:?}",
                raw.domain
            )));
        }
        if !is_sha256_hex(&raw.kb_index_hash) {
            return Err(KbRefusal::BadManifest(
                "kb_index_hash is not a SHA-256".into(),
            ));
        }
        if raw.sources.is_empty() {
            return Err(KbRefusal::BadManifest("no sources".into()));
        }
        let mut dumps = BTreeMap::new();
        for s in raw.sources {
            if !is_dump_name(&s.file) {
                return Err(KbRefusal::BadManifest(format!(
                    "{:?} is not a dump file name",
                    s.file
                )));
            }
            if !is_sha256_hex(&s.canonical_dump_sha256) {
                return Err(KbRefusal::BadManifest(format!(
                    "{}: digest is not a SHA-256",
                    s.file
                )));
            }
            if dumps
                .insert(s.file.clone(), s.canonical_dump_sha256)
                .is_some()
            {
                return Err(KbRefusal::BadManifest(format!("{} listed twice", s.file)));
            }
        }
        Ok(Self {
            kb_index_hash: raw.kb_index_hash,
            dumps,
        })
    }

    /// A manifest pinning exactly `dumps` (name, bytes) — for tests.
    #[cfg(test)]
    pub(crate) fn for_dumps(dumps: &[(&str, &[u8])]) -> Self {
        Self {
            kb_index_hash: "0".repeat(64),
            dumps: dumps
                .iter()
                .map(|(n, b)| (n.to_string(), sha256_hex(b)))
                .collect(),
        }
    }

    /// The `kb_index_hash` the manifest records (logged at open).
    pub fn kb_index_hash(&self) -> &str {
        &self.kb_index_hash
    }

    /// The pinned dump file names, sorted.
    pub fn dump_names(&self) -> impl Iterator<Item = &str> {
        self.dumps.keys().map(String::as_str)
    }

    /// Read every pinned dump from `dir` and check it against the manifest.
    ///
    /// Refused: a directory that cannot be listed, any `*.jsonl` the
    /// manifest does not list, a pinned dump that is absent, not a regular
    /// file, larger than [`MAX_DUMP_BYTES`] or with another digest.
    /// Returns `(name, bytes)` in name order; the bytes are those hashed.
    pub fn read_verified(&self, dir: &Path) -> Result<Vec<(String, Vec<u8>)>, KbRefusal> {
        let entries = std::fs::read_dir(dir).map_err(|e| KbRefusal::Missing {
            dir: dir.to_path_buf(),
            detail: e.to_string(),
        })?;
        let mut present = BTreeSet::new();
        for entry in entries {
            let entry = entry.map_err(|e| KbRefusal::Missing {
                dir: dir.to_path_buf(),
                detail: e.to_string(),
            })?;
            let path = entry.path();
            if path.extension().is_none_or(|x| x != "jsonl") {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if !self.dumps.contains_key(&name) {
                return Err(KbRefusal::Unlisted {
                    dir: dir.to_path_buf(),
                    file: name,
                });
            }
            present.insert(name);
        }
        let mut out = Vec::with_capacity(self.dumps.len());
        for (name, expected) in &self.dumps {
            if !present.contains(name) {
                return Err(KbRefusal::Missing {
                    dir: dir.to_path_buf(),
                    detail: format!("{name} absent"),
                });
            }
            let bytes = read_dump(&dir.join(name)).map_err(|detail| KbRefusal::Unreadable {
                file: name.clone(),
                detail,
            })?;
            let actual = sha256_hex(&bytes);
            if &actual != expected {
                return Err(KbRefusal::Mismatch {
                    file: name.clone(),
                    expected: expected.clone(),
                    actual,
                });
            }
            out.push((name.clone(), bytes));
        }
        Ok(out)
    }
}

/// One regular file of at most [`MAX_DUMP_BYTES`]. `O_NONBLOCK` keeps a
/// FIFO planted under a dump's name from stalling the agent's start.
fn read_dump(path: &Path) -> Result<Vec<u8>, String> {
    let mut f = File::options()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| e.to_string())?;
    let meta = f.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    if meta.len() > MAX_DUMP_BYTES {
        return Err(format!("{} bytes, over {MAX_DUMP_BYTES}", meta.len()));
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    (&mut f)
        .take(MAX_DUMP_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_DUMP_BYTES {
        return Err(format!("over {MAX_DUMP_BYTES} bytes"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &[u8] = b"{\"id\":\"a\"}\n";
    const B: &[u8] = b"{\"id\":\"b\"}\n";

    fn dir_with(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for (n, b) in files {
            std::fs::write(d.path().join(n), b).unwrap();
        }
        d
    }

    #[test]
    fn pinned_manifest_names_both_canonical_dumps() {
        let m = KbManifest::pinned().expect("the built-in kb_index.json parses");
        assert_eq!(
            m.dump_names().collect::<Vec<_>>(),
            ["mitre-attack.jsonl", "sigma.jsonl"]
        );
        assert!(is_sha256_hex(m.kb_index_hash()));
    }

    #[test]
    fn pinned_dumps_read_in_name_order() {
        let m = KbManifest::for_dumps(&[("b.jsonl", B), ("a.jsonl", A)]);
        let d = dir_with(&[("a.jsonl", A), ("b.jsonl", B), ("notes.txt", b"x")]);
        let got = m.read_verified(d.path()).unwrap();
        assert_eq!(
            got,
            vec![
                ("a.jsonl".into(), A.to_vec()),
                ("b.jsonl".into(), B.to_vec())
            ]
        );
    }

    #[test]
    fn tampered_dump_is_a_mismatch() {
        let m = KbManifest::for_dumps(&[("a.jsonl", A)]);
        let d = dir_with(&[("a.jsonl", b"{\"id\":\"evil\"}\n")]);
        let e = m.read_verified(d.path()).unwrap_err();
        assert!(
            matches!(e, KbRefusal::Mismatch { ref file, .. } if file == "a.jsonl"),
            "{e}"
        );
    }

    #[test]
    fn unlisted_jsonl_is_refused() {
        let m = KbManifest::for_dumps(&[("a.jsonl", A)]);
        let d = dir_with(&[("a.jsonl", A), ("zz-extra.jsonl", B)]);
        let e = m.read_verified(d.path()).unwrap_err();
        assert!(
            matches!(e, KbRefusal::Unlisted { ref file, .. } if file == "zz-extra.jsonl"),
            "{e}"
        );
    }

    #[test]
    fn missing_dump_or_dir_is_missing() {
        let m = KbManifest::for_dumps(&[("a.jsonl", A), ("b.jsonl", B)]);
        let d = dir_with(&[("a.jsonl", A)]);
        assert!(m.read_verified(d.path()).unwrap_err().is_missing());
        let empty = tempfile::tempdir().unwrap();
        assert!(m.read_verified(empty.path()).unwrap_err().is_missing());
        assert!(m
            .read_verified(&empty.path().join("absent"))
            .unwrap_err()
            .is_missing());
    }

    #[test]
    fn fifo_under_a_dump_name_does_not_block() {
        let m = KbManifest::for_dumps(&[("a.jsonl", A)]);
        let d = tempfile::tempdir().unwrap();
        let p = std::ffi::CString::new(
            d.path()
                .join("a.jsonl")
                .into_os_string()
                .into_encoded_bytes(),
        )
        .unwrap();
        assert_eq!(unsafe { libc::mkfifo(p.as_ptr(), 0o600) }, 0);
        let e = m.read_verified(d.path()).unwrap_err();
        assert!(matches!(e, KbRefusal::Unreadable { .. }), "{e}");
    }

    #[test]
    fn malformed_manifests_are_refused() {
        let ok = |file: &str, sha: &str| {
            format!(
                r#"{{"domain":"NN-RAG-KB-CANON-v1","kb_index_hash":"{h}","sources":[{{"canonical_dump_sha256":"{sha}","file":"{file}"}}]}}"#,
                h = "a".repeat(64)
            )
        };
        assert!(KbManifest::parse(&ok("x.jsonl", &"b".repeat(64))).is_ok());
        for bad in [
            ok("../x.jsonl", &"b".repeat(64)),
            ok(".x.jsonl", &"b".repeat(64)),
            ok("x.txt", &"b".repeat(64)),
            ok("x.jsonl", &"B".repeat(64)),
            ok("x.jsonl", "short"),
            r#"{"domain":"NN-RAG-KB-CANON-v1","kb_index_hash":"x","sources":[]}"#.to_string(),
            ok("x.jsonl", &"b".repeat(64)).replace("CANON-v1", "CANON-v2"),
        ] {
            assert!(
                matches!(KbManifest::parse(&bad), Err(KbRefusal::BadManifest(_))),
                "{bad}"
            );
        }
        let twice = format!(
            r#"{{"domain":"NN-RAG-KB-CANON-v1","kb_index_hash":"{h}","sources":[{{"canonical_dump_sha256":"{h}","file":"x.jsonl"}},{{"canonical_dump_sha256":"{h}","file":"x.jsonl"}}]}}"#,
            h = "a".repeat(64)
        );
        assert!(KbManifest::parse(&twice).is_err());
    }
}
