//! eBPF-object provenance: the one place that decides "was this
//! compiled `.o` built from the current source tree?"
//!
//! ## Why this crate exists
//!
//! `agent-ebpf/` is a **separate cargo project** (nightly + `rust-src`
//! + the `bpfel-unknown-none` target), deliberately excluded from the
//! userland workspace (root `Cargo.toml` `exclude = ["agent-ebpf"]`).
//! Only `cargo xtask build[-ebpf]` compiles it. `agent/build.rs` then
//! `include_bytes!`-embeds whatever `.o` is sitting in
//! `agent-ebpf/target/…` into the agent binary.
//!
//! The trap that cost a night of debugging: a plain
//! `cargo build --workspace` (or any IDE / CI userland build) does
//! **not** rebuild the eBPF object — it silently embeds whatever stale
//! `.o` is on disk. When the kernel↔userland struct keeps the same
//! *size* (e.g. a new field carved out of reclaimed padding, like
//! `ProcessSpawnRaw::parent_is_kthread`), the `bytemuck` size-check at
//! decode time passes and the staleness is **invisible** — the agent
//! runs against month-old kernel logic and silently mis-fires.
//!
//! A size check can never catch that. The only thing that can is a
//! **provenance** check: hash the source that *should* have produced
//! the `.o`, record it next to the `.o` at build time (the "stamp"),
//! and refuse — loudly, at build time — to embed a `.o` whose stamp
//! does not match the current source.
//!
//! ## The contract
//!
//! - [`ebpf_source_hash`] hashes the eBPF build's **source closure**
//!   (the eBPF crate's sources + manifests + toolchain pin, plus the
//!   shared `common/` wire crate the `.o` compiles in).
//! - `cargo xtask build-ebpf` calls [`write_stamp`] right after a
//!   successful compile.
//! - `agent/build.rs` calls [`read_stamp`] + [`ebpf_source_hash`] and
//!   compares; mismatch (or a present-but-unstamped `.o`) is a hard
//!   build failure.
//!
//! Both sides MUST compute the hash byte-for-byte identically, which
//! is the entire reason this is one shared crate rather than two
//! copies of a walk-and-hash loop.

use std::{
    fs,
    io,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

/// Relative path (from the repo root) of the compiled eBPF object that
/// `agent/build.rs` embeds. The eBPF crate builds release-only (the
/// verifier needs it), so this is always the `release` artifact.
pub const ARTIFACT_RELPATH: &str =
    "agent-ebpf/target/bpfel-unknown-none/release/northnarrow-agent-ebpf";

/// The provenance stamp sits next to the artifact with a `.buildhash`
/// suffix. `cargo xtask build-ebpf` writes it; `agent/build.rs` reads
/// it. Living under `agent-ebpf/target/` means it is gitignored and is
/// recreated by every eBPF build — exactly like the `.o` itself.
pub const STAMP_RELPATH: &str =
    "agent-ebpf/target/bpfel-unknown-none/release/northnarrow-agent-ebpf.buildhash";

/// Stamp format version, folded into the hash. Bump this if the set of
/// hashed inputs or the framing below ever changes — bumping
/// invalidates every existing stamp, which forces a clean eBPF rebuild
/// rather than risking a hash that means different things across agent
/// versions.
pub const STAMP_VERSION: &str = "nn-ebpf-buildhash-v1";

/// Absolute path to the compiled eBPF object, given the repo root.
pub fn ebpf_artifact_path(repo_root: &Path) -> PathBuf {
    repo_root.join(ARTIFACT_RELPATH)
}

/// Absolute path to the provenance stamp, given the repo root.
pub fn ebpf_stamp_path(repo_root: &Path) -> PathBuf {
    repo_root.join(STAMP_RELPATH)
}

/// SHA-256 of an arbitrary byte slice, lowercase hex. Exposed so
/// `agent/build.rs` can fingerprint the exact `.o` bytes it embeds
/// (the runtime integrity check compares against this) without pulling
/// its own `sha2` dependency or risking a different digest encoding.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    to_hex(&hasher.finalize())
}

/// The deterministic, sorted list of files that make up the eBPF
/// build's **source closure** — everything whose change should force a
/// recompile of the `.o`:
///
/// - every `.rs` under `agent-ebpf/src/` (the program itself), and
/// - every `.rs` under `common/src/` (the shared kernel↔userland wire
///   types the `.o` links in — a change here that is NOT recompiled
///   into the `.o` is the precise failure mode this guards), and
/// - the eBPF crate's manifest + lockfile + toolchain pin +
///   cargo config (dependency / toolchain / target drift all change
///   the emitted object), and
/// - `common`'s manifest (feature-flag shape affects the no_std build).
///
/// Scoping `common/` at the whole-crate granularity is deliberately
/// **over-conservative**: editing a userland-only file there forces an
/// otherwise-unnecessary eBPF rebuild, but that is the safe direction
/// (a spurious rebuild costs seconds; a missed one is the night-long
/// incident). Returned sorted by repo-relative path for a stable hash
/// and a stable `cargo:rerun-if-changed` set.
pub fn source_inputs(repo_root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = Vec::new();

    collect_rs(&repo_root.join("agent-ebpf/src"), &mut files)?;
    collect_rs(&repo_root.join("common/src"), &mut files)?;

    // Exact files: include each only if present. Their presence/
    // absence is itself captured (an absent file simply contributes
    // nothing), so adding a previously-missing Cargo.lock changes the
    // hash and triggers a rebuild — the safe behaviour.
    for rel in EXACT_INPUTS {
        let p = repo_root.join(rel);
        if p.is_file() {
            files.push(p);
        }
    }

    files.sort();
    files.dedup();
    Ok(files)
}

/// Non-`.rs` inputs that still determine the compiled object.
const EXACT_INPUTS: &[&str] = &[
    "agent-ebpf/Cargo.toml",
    "agent-ebpf/Cargo.lock",
    "agent-ebpf/rust-toolchain.toml",
    "agent-ebpf/.cargo/config.toml",
    "common/Cargo.toml",
];

/// Hash the eBPF source closure ([`source_inputs`]) into a lowercase
/// hex SHA-256. Framing is length-prefixed per file and keyed by the
/// repo-relative path, so a rename, a content edit, or an added/
/// removed file all change the digest. [`STAMP_VERSION`] is folded in
/// first.
pub fn ebpf_source_hash(repo_root: &Path) -> io::Result<String> {
    let inputs = source_inputs(repo_root)?;
    let mut hasher = Sha256::new();
    hasher.update(STAMP_VERSION.as_bytes());
    hasher.update([0u8]);
    for path in &inputs {
        let rel = path.strip_prefix(repo_root).unwrap_or(path);
        // Forward-slash normalise so the digest is path-separator
        // stable (belt-and-suspenders; this tree is Linux-only).
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let bytes = fs::read(path)?;
        hasher.update((rel_str.len() as u64).to_le_bytes());
        hasher.update(rel_str.as_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    Ok(to_hex(&hasher.finalize()))
}

/// Write the provenance stamp next to the `.o`, atomically (write to a
/// temp sibling, then rename). Called by `cargo xtask build-ebpf`
/// after a verified-successful compile. The file is human-inspectable:
/// `<STAMP_VERSION>\n<hash>\n`.
pub fn write_stamp(repo_root: &Path, source_hash: &str) -> io::Result<()> {
    let stamp = ebpf_stamp_path(repo_root);
    let parent = stamp
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "stamp path has no parent"))?;
    fs::create_dir_all(parent)?;
    let contents = format!("{STAMP_VERSION}\n{source_hash}\n");
    let tmp = stamp.with_extension("buildhash.tmp");
    fs::write(&tmp, contents.as_bytes())?;
    fs::rename(&tmp, &stamp)?;
    Ok(())
}

/// Read the source hash recorded in the stamp, if present and valid.
///
/// - `Ok(None)`  — no stamp on disk (the `.o` was built by an unknown
///   path, or there is no `.o` at all).
/// - `Ok(Some(h))` — the recorded source hash.
/// - `Err`/`Ok(None)` on a malformed or wrong-version stamp: a stamp
///   whose first line is not the current [`STAMP_VERSION`] is treated
///   as absent so a format bump forces a clean rebuild rather than a
///   confusing compare against an incompatible value.
pub fn read_stamp(repo_root: &Path) -> io::Result<Option<String>> {
    let stamp = ebpf_stamp_path(repo_root);
    let raw = match fs::read_to_string(&stamp) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut lines = raw.lines();
    match (lines.next(), lines.next()) {
        (Some(ver), Some(hash)) if ver == STAMP_VERSION && !hash.trim().is_empty() => {
            Ok(Some(hash.trim().to_string()))
        }
        // Present but unreadable / stale-format: surface as "no usable
        // stamp" so the caller's present-but-unstamped path fires.
        _ => Ok(None),
    }
}

/// Recursively collect `*.rs` files under `dir` into `out`. A missing
/// directory is an error (the eBPF + common source dirs always exist;
/// their absence means a broken checkout, which should fail loudly
/// rather than silently hash an empty closure).
fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect_rs(&path, out)?;
        } else if ft.is_file() && path.extension().map(|e| e == "rs").unwrap_or(false) {
            out.push(path);
        }
    }
    Ok(())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_matches_known_vector() {
        // NIST: SHA-256("abc")
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // Empty input.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hash_is_deterministic_and_change_sensitive() {
        let dir = tempdir();
        let root = dir.path();
        write(root, "agent-ebpf/src/main.rs", b"fn main() {}");
        write(root, "common/src/lib.rs", b"// wire");
        write(root, "agent-ebpf/Cargo.toml", b"[package]\nname='x'");

        let h1 = ebpf_source_hash(root).unwrap();
        let h2 = ebpf_source_hash(root).unwrap();
        assert_eq!(h1, h2, "same tree → same hash");

        // Editing a source file changes the hash.
        write(root, "common/src/lib.rs", b"// wire CHANGED");
        let h3 = ebpf_source_hash(root).unwrap();
        assert_ne!(h1, h3, "a content edit must change the hash");

        // Adding a new source file changes the hash.
        write(root, "agent-ebpf/src/extra.rs", b"// new");
        let h4 = ebpf_source_hash(root).unwrap();
        assert_ne!(h3, h4, "a new file must change the hash");
    }

    #[test]
    fn rename_changes_hash_even_with_identical_bytes() {
        let dir = tempdir();
        let root = dir.path();
        write(root, "agent-ebpf/src/a.rs", b"same bytes");
        write(root, "common/src/lib.rs", b"x");
        let before = ebpf_source_hash(root).unwrap();

        // Rename a.rs → b.rs, identical content.
        fs::remove_file(root.join("agent-ebpf/src/a.rs")).unwrap();
        write(root, "agent-ebpf/src/b.rs", b"same bytes");
        let after = ebpf_source_hash(root).unwrap();
        assert_ne!(before, after, "path is keyed into the digest");
    }

    #[test]
    fn stamp_round_trips_and_rejects_wrong_version() {
        let dir = tempdir();
        let root = dir.path();
        // No stamp yet.
        assert_eq!(read_stamp(root).unwrap(), None);

        write_stamp(root, "deadbeef").unwrap();
        assert_eq!(read_stamp(root).unwrap(), Some("deadbeef".to_string()));

        // A stamp written with a different version line reads as absent.
        let stamp = ebpf_stamp_path(root);
        fs::write(&stamp, b"some-other-version\ndeadbeef\n").unwrap();
        assert_eq!(
            read_stamp(root).unwrap(),
            None,
            "wrong-version stamp must read as absent (forces clean rebuild)"
        );
    }

    // ── tiny std-only test helpers (no tempfile dep in this crate) ──

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn tempdir() -> TmpDir {
        // Deterministic-enough unique dir under the OS temp root without
        // pulling `tempfile`: thread id + a static counter.
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let base = std::env::temp_dir().join(format!("ebpf-guard-test-{pid}-{n}"));
        fs::create_dir_all(&base).unwrap();
        TmpDir(base)
    }

    fn write(root: &Path, rel: &str, bytes: &[u8]) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, bytes).unwrap();
    }
}
