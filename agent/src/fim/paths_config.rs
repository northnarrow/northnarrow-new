//! Tappa 9 (C7) — FIM watched-paths configuration loader.
//!
//! Loads two files at agent boot:
//!
//! - `/etc/northnarrow/fim-paths.v1` — the curated default list
//!   shipped by `install.sh` (commit C7 / repo `configs/fim-paths.v1`).
//!   Format: one absolute path per line, `#` comments, blanks
//!   ignored. NO directives.
//! - `/etc/northnarrow/fim-paths.local` — the operator overlay
//!   per design §13 Q7. Supports BOTH `add:` and `disable:` over
//!   the v1 default list. Format: directive-prefixed lines —
//!   `+/absolute/path` to add, `-/absolute/path` to disable a
//!   default. Bare `#` introduces comments; blank lines are
//!   ignored. Bare path with no prefix is treated as `add` (so
//!   the file can be a plain extension list without operators
//!   having to learn the prefix scheme).
//!
//! Design choice: no YAML parser dependency. The two files are
//! line-oriented + 1-character directive prefix; a hand-rolled
//! reader is simpler than pulling `serde_yaml_ng` into the agent
//! crate for one config file each. Operators inspect both with
//! `cat` (no special tool needed) and edit with `vi`.
//!
//! Boot-time WARN per §13 Q7: every default path that
//! `fim-paths.local` disables emits a `WARN fim: default path
//! <P> disabled by operator config` line at agent boot. The
//! operator can't silently hide a regression.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};

use crate::config::overlay;

/// Default deploy location of the curated paths list. Matches
/// the path `install.sh` (Tappa 9 C7) drops the repo's
/// `configs/fim-paths.v1` to.
pub const DEFAULT_PATHS_V1: &str = "/etc/northnarrow/fim-paths.v1";

/// Default deploy location of the operator overlay file. The
/// overlay is OPTIONAL — a missing file means "no add or disable
/// adjustments" (the v1 list is used as-is).
pub const DEFAULT_PATHS_LOCAL: &str = "/etc/northnarrow/fim-paths.local";

/// Outcome of [`load_watched_paths`]. The `effective` set is the
/// one the agent registers into `WATCHED_PATHS`; the other fields
/// surface operator visibility (boot logs + `nn-admin fim status`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WatchedPathsLoad {
    /// Final ordered set of absolute paths the agent will watch.
    /// `BTreeSet` for deterministic iteration (audit-grade boot
    /// logs benefit from stable ordering).
    pub effective: BTreeSet<PathBuf>,
    /// Paths added by the operator overlay's `+` / bare-path lines.
    pub added: BTreeSet<PathBuf>,
    /// Paths the operator overlay disabled with a `-` line AND
    /// that were actually present in the default list. A `-` line
    /// targeting a non-default path is silently a no-op (already
    /// absent from `effective`) — surfaced separately as `unknown_disable`.
    pub disabled: BTreeSet<PathBuf>,
    /// `-` lines whose target was not in the default list. Surfaced
    /// so operators don't think they disabled something when they
    /// in fact targeted an already-absent path.
    pub unknown_disable: BTreeSet<PathBuf>,
}

/// Load + merge the two files. Either or both being missing is
/// tolerated:
///
/// - Missing `fim-paths.v1` → empty default list, only the overlay's
///   `+` lines populate `effective`. Surfaces a WARN — production
///   should always have v1 (install.sh drops it). Tests that don't
///   need v1 just omit the file.
/// - Missing `fim-paths.local` → no overlay; `effective` equals the
///   default list.
///
/// Errors propagate only on read/parse failures of a file that DID
/// exist. Missing-file is fine.
pub fn load_watched_paths(v1_path: &Path, local_path: &Path) -> Result<WatchedPathsLoad> {
    // Tappa 10.5 D1: the directive-parsing + merge + boot-WARN core
    // now lives in the shared `config::overlay` loader; this wrapper
    // adds the FIM-specific absolute-path validation and maps the
    // generic `String` entries back into `PathBuf`. Behaviour is
    // unchanged (the tests below pin the contract).
    let load = overlay::load_flat_list(
        "fim paths-config",
        v1_path,
        local_path,
        &validate_absolute_path,
    )?;
    Ok(WatchedPathsLoad {
        effective: load.effective.iter().map(PathBuf::from).collect(),
        added: load.added.iter().map(PathBuf::from).collect(),
        disabled: load.disabled.iter().map(PathBuf::from).collect(),
        unknown_disable: load.unknown_disable.iter().map(PathBuf::from).collect(),
    })
}

/// FIM entry shape rule: watched paths must be absolute.
fn validate_absolute_path(entry: &str) -> Result<()> {
    if !entry.starts_with('/') {
        return Err(anyhow!(
            "paths must be absolute (start with `/`), got `{entry}`"
        ));
    }
    Ok(())
}

/// Read the curated default list. Thin `PathBuf`-typed wrapper over
/// [`overlay::parse_default_list`] kept for the focused unit tests
/// below; production goes through [`load_watched_paths`].
#[cfg(test)]
fn read_default_list(path: &Path) -> Result<BTreeSet<PathBuf>> {
    Ok(overlay::parse_default_list(path, &validate_absolute_path)?
        .into_iter()
        .map(PathBuf::from)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// C7 #1: a v1-only file with no overlay yields exactly the
    /// v1 paths as `effective`; `added`, `disabled`, and
    /// `unknown_disable` are empty.
    #[test]
    fn load_v1_only_no_overlay() {
        let dir = TempDir::new().unwrap();
        let v1 = dir.path().join("fim-paths.v1");
        let local = dir.path().join("fim-paths.local");
        std::fs::write(
            &v1,
            "# header comment\n\
             /usr/sbin/sshd\n\
             /etc/passwd\n\
             \n\
             /etc/shadow   # inline comment\n",
        )
        .unwrap();
        // local file ABSENT — that's the no-overlay case.
        let out = load_watched_paths(&v1, &local).expect("load");
        let expected: BTreeSet<PathBuf> = ["/usr/sbin/sshd", "/etc/passwd", "/etc/shadow"]
            .iter()
            .map(PathBuf::from)
            .collect();
        assert_eq!(out.effective, expected);
        assert!(out.added.is_empty());
        assert!(out.disabled.is_empty());
        assert!(out.unknown_disable.is_empty());
    }

    /// C7 #2: operator overlay with both `add:` and `disable:` lines.
    /// Verifies the merge: defaults minus disables plus adds. The
    /// `disabled` set in the outcome captures only paths that WERE
    /// in the default list (so a typo'd disable surfaces separately
    /// as `unknown_disable`).
    #[test]
    fn load_v1_with_local_add_and_disable() {
        let dir = TempDir::new().unwrap();
        let v1 = dir.path().join("fim-paths.v1");
        let local = dir.path().join("fim-paths.local");
        std::fs::write(&v1, "/usr/sbin/sshd\n/var/log/wtmp\n/etc/passwd\n").unwrap();
        std::fs::write(
            &local,
            "# operator overlay\n\
             +/opt/myapp/bin/myapp\n\
             /etc/myapp/config.toml     # bare path = add\n\
             -/var/log/wtmp\n\
             -/etc/nonexistent          # unknown disable\n",
        )
        .unwrap();
        let out = load_watched_paths(&v1, &local).expect("load");

        let expected_effective: BTreeSet<PathBuf> = [
            "/usr/sbin/sshd",
            "/etc/passwd",
            "/opt/myapp/bin/myapp",
            "/etc/myapp/config.toml",
        ]
        .iter()
        .map(PathBuf::from)
        .collect();
        assert_eq!(out.effective, expected_effective);

        assert!(out.added.contains(&PathBuf::from("/opt/myapp/bin/myapp")));
        assert!(out.added.contains(&PathBuf::from("/etc/myapp/config.toml")));
        assert!(out.disabled.contains(&PathBuf::from("/var/log/wtmp")));
        assert!(out
            .unknown_disable
            .contains(&PathBuf::from("/etc/nonexistent")));
    }

    /// C7 #3: missing v1 + missing local → empty load (warn, not
    /// error). Useful for test agents that don't ship a paths file.
    #[test]
    fn load_both_missing_returns_empty() {
        let dir = TempDir::new().unwrap();
        let out = load_watched_paths(
            &dir.path().join("missing.v1"),
            &dir.path().join("missing.local"),
        )
        .expect("missing files tolerated");
        assert!(out.effective.is_empty());
        assert!(out.added.is_empty());
        assert!(out.disabled.is_empty());
        assert!(out.unknown_disable.is_empty());
    }

    /// C7 #4: a malformed v1 (relative path) is rejected up-front
    /// rather than silently registering a non-absolute path. The
    /// agent boot continues (load_watched_paths returns Err but
    /// the WARN-then-empty path in `load_watched_paths` keeps the
    /// agent up); this test confirms the inner `read_default_list`
    /// surfaces the diagnostic.
    #[test]
    fn read_default_list_rejects_relative_path() {
        let dir = TempDir::new().unwrap();
        let v1 = dir.path().join("fim-paths.v1");
        std::fs::write(&v1, "relative/path/no-leading-slash\n").unwrap();
        let err = read_default_list(&v1).expect_err("relative paths must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("must be absolute"),
            "expected absolute-path diagnostic, got: {msg}"
        );
    }

    /// C7 #5: a v1 file that accidentally contains `+`/`-` prefixed
    /// lines (operator copied a `.local` template over `v1`) is
    /// rejected up-front so the install error surfaces at boot.
    #[test]
    fn read_default_list_rejects_directive_prefixes() {
        let dir = TempDir::new().unwrap();
        let v1 = dir.path().join("fim-paths.v1");
        std::fs::write(&v1, "/usr/sbin/sshd\n+/oops/operator-overlay-syntax\n").unwrap();
        let err = read_default_list(&v1).expect_err("v1 must reject +/- prefixes");
        let msg = err.to_string();
        assert!(
            msg.contains("local-overlay only"),
            "expected directive-prefix diagnostic, got: {msg}"
        );
    }
}
