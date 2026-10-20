//! One private scratch directory per fuzzing process (external audit
//! WDG-R09, NN-AUD-375). The targets wrote `$TMPDIR/nn-fuzz-*-<pid>` with
//! `fs::write`, which follows a link planted at that predictable name, and
//! left it behind. Now: one `tempfile` directory (mode 0700, a random
//! name, never an entry that already exists), files in it created
//! exclusively (`O_CREAT | O_EXCL`: no link is followed, the AUT-003
//! pattern), and the directory removed when libFuzzer exits normally. A
//! crash leaves it, next to the crash artefact.
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();

extern "C" fn remove_at_exit() {
    if let Some(d) = DIR.get() {
        let _ = std::fs::remove_dir_all(d.path());
    }
}

/// The process's scratch directory, created on first use.
pub fn dir(prefix: &str) -> &'static Path {
    DIR.get_or_init(|| {
        let d = tempfile::Builder::new()
            .prefix(prefix)
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("a private scratch directory");
        // SAFETY: registers a plain `extern "C"` function, which only reads
        // the OnceLock above (set before it can run).
        unsafe { libc::atexit(remove_at_exit) };
        d
    })
    .path()
}

/// Replace `dir/name` with `body`: whatever is at the name is unlinked
/// (`unlink` never follows a link) and the file is created exclusively.
#[allow(dead_code)] // a module of every target that writes; not all rewrite
pub fn replace(dir: &Path, name: &str, body: &[u8]) -> std::io::Result<PathBuf> {
    let path = dir.join(name);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?
        .write_all(body)?;
    Ok(path)
}
