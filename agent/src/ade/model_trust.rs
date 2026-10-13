//! External audit LLMR-004: the ADE model and its tokenizer are loaded only
//! from where nobody but root can change them.
//!
//! The agent runs as root and fed whatever GGUF and `tokenizer.json` sat at
//! the configured path to the model, with no check at all — and the default
//! path was in a user's home. Whoever can rewrite the file, or any
//! directory on its path, chooses the model's verdicts (a tailored `Allow`,
//! or output that keeps the escalation busy) while the logs look normal,
//! and hands candle's GGUF parser a file of their making.
//!
//! [`open_trusted`] opens a model artefact the way `sshd`'s StrictModes
//! treats its key files: the path resolved, every directory on it owned by
//! root (or the agent's own user) and not writable by group or others —
//! a sticky directory such as `/tmp` excepted, since nobody else can then
//! replace what root owns in it — and the file itself, opened without
//! following a link, a regular file with the same owner and no group or
//! other write bit. The caller reads the descriptor it got: what was
//! checked is what is parsed.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::error::AdeError;

const GROUP_OR_OTHER_WRITE: u32 = 0o022;
const STICKY: u32 = 0o1000;

/// Open `path` if it, and the directories leading to it, can only have
/// been written by root (or the agent's own user). Returns the descriptor
/// and the resolved path.
pub fn open_trusted(path: &Path) -> Result<(File, PathBuf), AdeError> {
    let resolved = path
        .canonicalize()
        .map_err(|e| refuse(path, &format!("resolving: {e}")))?;
    let trusted = |uid: u32| uid == 0 || uid == own_uid();
    let mut dir = resolved.parent();
    while let Some(d) = dir {
        let m = d
            .metadata()
            .map_err(|e| refuse(path, &format!("{}: {e}", d.display())))?;
        if !trusted(m.uid()) {
            return Err(refuse(
                path,
                &format!("directory {} is owned by uid {}", d.display(), m.uid()),
            ));
        }
        if m.mode() & GROUP_OR_OTHER_WRITE != 0 && m.mode() & STICKY == 0 {
            return Err(refuse(
                path,
                &format!(
                    "directory {} is writable by group or others (mode {:o})",
                    d.display(),
                    m.mode() & 0o7777
                ),
            ));
        }
        dir = d.parent();
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&resolved)
        .map_err(|e| refuse(path, &format!("opening {}: {e}", resolved.display())))?;
    let m = file
        .metadata()
        .map_err(|e| refuse(path, &format!("stat: {e}")))?;
    if !m.file_type().is_file() {
        return Err(refuse(path, "not a regular file"));
    }
    if !trusted(m.uid()) {
        return Err(refuse(path, &format!("owned by uid {}", m.uid())));
    }
    if m.mode() & GROUP_OR_OTHER_WRITE != 0 {
        return Err(refuse(
            path,
            &format!("writable by group or others (mode {:o})", m.mode() & 0o7777),
        ));
    }
    Ok((file, resolved))
}

fn own_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn refuse(path: &Path, why: &str) -> AdeError {
    AdeError::ModelUntrusted(format!(
        "refusing the model artefact {} (external audit LLMR-004): {why}",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn set_mode(p: &Path, mode: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// A tree the agent's own user owns, closed to others (a temporary
    /// directory under the sticky `/tmp`): trusted, and the descriptor is
    /// the file's.
    #[test]
    fn a_closed_tree_is_trusted() {
        let tmp = TempDir::new().unwrap();
        set_mode(tmp.path(), 0o755);
        let models = tmp.path().join("models");
        std::fs::create_dir(&models).unwrap();
        set_mode(&models, 0o755);
        let gguf = models.join("m.gguf");
        std::fs::write(&gguf, b"GGUF").unwrap();
        set_mode(&gguf, 0o644);
        let (mut f, resolved) = open_trusted(&gguf).unwrap();
        let mut s = String::new();
        std::io::Read::read_to_string(&mut f, &mut s).unwrap();
        assert_eq!(s, "GGUF");
        assert_eq!(resolved, gguf.canonicalize().unwrap());
    }

    /// Writable by others: the file, or any directory on its path.
    #[test]
    fn anything_others_can_write_is_refused() {
        let tmp = TempDir::new().unwrap();
        set_mode(tmp.path(), 0o755);
        let models = tmp.path().join("models");
        std::fs::create_dir(&models).unwrap();
        let gguf = models.join("m.gguf");
        std::fs::write(&gguf, b"GGUF").unwrap();
        set_mode(&models, 0o755);
        set_mode(&gguf, 0o666);
        assert!(open_trusted(&gguf).is_err(), "file writable by others");
        set_mode(&gguf, 0o644);
        set_mode(&models, 0o777);
        assert!(open_trusted(&gguf).is_err(), "directory writable by others");
        set_mode(&models, 0o1777);
        assert!(
            open_trusted(&gguf).is_ok(),
            "a sticky directory keeps root's file"
        );
        set_mode(&models, 0o775);
        assert!(
            open_trusted(&gguf).is_err(),
            "directory writable by its group"
        );
    }

    /// A link is followed only to check where it leads: the target's own
    /// path must be trusted, and what is opened is the target itself.
    #[test]
    fn a_link_is_judged_by_where_it_leads() {
        let tmp = TempDir::new().unwrap();
        set_mode(tmp.path(), 0o755);
        let real = tmp.path().join("real");
        let open_dir = tmp.path().join("open");
        std::fs::create_dir(&real).unwrap();
        std::fs::create_dir(&open_dir).unwrap();
        set_mode(&real, 0o755);
        set_mode(&open_dir, 0o777);
        let target = open_dir.join("m.gguf");
        std::fs::write(&target, b"x").unwrap();
        set_mode(&target, 0o644);
        let link = real.join("m.gguf");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(
            open_trusted(&link).is_err(),
            "the link lives in a closed directory, its target does not"
        );
    }

    #[test]
    fn a_missing_file_or_a_directory_is_refused() {
        let tmp = TempDir::new().unwrap();
        set_mode(tmp.path(), 0o755);
        assert!(open_trusted(&tmp.path().join("absent.gguf")).is_err());
        assert!(open_trusted(tmp.path()).is_err());
    }
}
