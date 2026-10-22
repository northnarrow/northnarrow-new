//! Tappa 9 (C7) — FIM watched-paths configuration loader.
//!
//! Loads two files at agent boot:
//!
//! - `/etc/northnarrow/fim-paths.v1` — the curated default list
//!   shipped by `install.sh` (commit C7 / repo `configs/fim-paths.v1`).
//!   Format: one absolute path per line, `#` comments, blanks
//!   ignored. NO directives. The agent carries a copy of it
//!   ([`BUILTIN_PATHS_V1`]) for a host where the file cannot be read.
//! - `/etc/northnarrow/fim-paths.local` — the operator overlay
//!   per design §13 Q7. Supports BOTH `add:` and `disable:` over
//!   the v1 default list. Format: directive-prefixed lines —
//!   `+/absolute/path` to add, `-/absolute/path` to disable a
//!   default. Bare `#` introduces comments; blank lines are
//!   ignored. Bare path with no prefix is treated as `add` (so
//!   the file can be a plain extension list without operators
//!   having to learn the prefix scheme). It reaches the loader as
//!   the signed-overlay gate verified it (Tappa 10.8, external audit
//!   LLMR-013).
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

use crate::config::overlay::{self, DefaultsSource, Shipped};
use crate::config::overlay_auth::Verified;

/// Default deploy location of the curated paths list. Matches
/// the path `install.sh` (Tappa 9 C7) drops the repo's
/// `configs/fim-paths.v1` to.
pub const DEFAULT_PATHS_V1: &str = "/etc/northnarrow/fim-paths.v1";

/// Default deploy location of the operator overlay file. The
/// overlay is OPTIONAL — a missing file means "no add or disable
/// adjustments" (the v1 list is used as-is).
pub const DEFAULT_PATHS_LOCAL: &str = "/etc/northnarrow/fim-paths.local";

/// External audit LLMR-016: the shipped default list, built in — used
/// when `fim-paths.v1` cannot be read (FIM used to watch only the
/// overlay's additions then).
pub const BUILTIN_PATHS_V1: &str =
    include_str!(concat!(env!("NN_REPO_ROOT"), "/configs/fim-paths.v1"));

/// External audit LLMR-015 (NN-AUD-327): SHA-256 of every `fim-paths.v1`
/// an earlier release shipped (the history of `configs/`). The agent
/// watches its built-in list over one of these, and `install.sh`
/// (`SHIPPED_V1_EARLIER`, kept equal by a test) replaces it.
pub const EARLIER_PATHS_V1_SHA256: &[&str] = &[
    // Tappa 9 C7 (1f7f011)
    "6baec5b5f0dfc92bdf91a0426b8d3693bd4b4a7b25df79e6ff9aa2298b906659",
    // Tappa 10.5 D3 (a634008)
    "99e3364b81cf77ccd51cda88e80bc71a45b13e7b75c7ff480b195e157ab3011a",
    // Tappa 9.5.1 D2 (dffc6b8), before lab PR 188 added the restore links
    "3fc62222695e595a26069123393850cfe917c614d863947248240a3b41810c9b",
];
/// The shipped `fim-paths.v1` (built-in copy, earlier ones).
pub const FIM_PATHS_SHIPPED: Shipped<'static> =
    Shipped::new(BUILTIN_PATHS_V1, EARLIER_PATHS_V1_SHA256);

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
    /// Where the defaults came from (external audit LLMR-016).
    pub defaults: DefaultsSource,
}

/// Load + merge the default list and the operator overlay:
///
/// - the defaults are the shipped list ([`BUILTIN_PATHS_V1`]):
///   `fim-paths.v1` when it is that copy; unreadable, an earlier
///   release's or edited by hand → the built-in copy, a WARN or an ERROR,
///   and `defaults` says so (the caller records the unreadable and the
///   edited ones — external audit LLMR-016, LLMR-015).
/// - `local` is the overlay as the gate verified it; none → `effective`
///   equals the default list.
pub fn load_watched_paths(v1_path: &Path, local: &Verified) -> Result<WatchedPathsLoad> {
    load_watched_paths_with(v1_path, FIM_PATHS_SHIPPED, local)
}

/// [`load_watched_paths`] with the shipped defaults given.
fn load_watched_paths_with(
    v1_path: &Path,
    shipped: Shipped<'_>,
    local: &Verified,
) -> Result<WatchedPathsLoad> {
    // Tappa 10.5 D1: the directive-parsing + merge + boot-WARN core
    // now lives in the shared `config::overlay` loader; this wrapper
    // adds the FIM-specific absolute-path validation and maps the
    // generic `String` entries back into `PathBuf`. Behaviour is
    // unchanged (the tests below pin the contract).
    let load = overlay::load_flat_list(
        "fim paths-config",
        v1_path,
        shipped,
        local,
        &validate_absolute_path,
    )?;
    Ok(WatchedPathsLoad {
        effective: load.effective.iter().map(PathBuf::from).collect(),
        added: load.added.iter().map(PathBuf::from).collect(),
        disabled: load.disabled.iter().map(PathBuf::from).collect(),
        unknown_disable: load.unknown_disable.iter().map(PathBuf::from).collect(),
        defaults: load.defaults,
    })
}

/// FIM entry shape rule: watched paths must be absolute.
pub(crate) fn validate_absolute_path(entry: &str) -> Result<()> {
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

    /// The overlay at `path` as a gate that accepts it hands it over.
    fn verified(path: &Path) -> Verified {
        match std::fs::read_to_string(path) {
            Ok(text) => Verified::Content {
                path: path.to_path_buf(),
                text,
            },
            Err(_) => Verified::Missing,
        }
    }

    /// Load `v1` as the list the agent was built with (its own content is
    /// the built-in copy): these tests are about parsing and the overlay.
    fn load_own(v1: &Path, local: &Verified) -> WatchedPathsLoad {
        let own = std::fs::read_to_string(v1).unwrap();
        load_watched_paths_with(v1, Shipped::new(&own, &[]), local).expect("load")
    }

    /// C7 #1: a v1-only file with no overlay yields exactly the
    /// v1 paths as `effective`; `added`, `disabled`, and
    /// `unknown_disable` are empty.
    #[test]
    fn load_v1_only_no_overlay() {
        let dir = TempDir::new().unwrap();
        let v1 = dir.path().join("fim-paths.v1");
        std::fs::write(
            &v1,
            "# header comment\n\
             /usr/sbin/sshd\n\
             /etc/passwd\n\
             \n\
             /etc/shadow   # inline comment\n",
        )
        .unwrap();
        // No overlay — the common case.
        let out = load_own(&v1, &Verified::Missing);
        let expected: BTreeSet<PathBuf> = ["/usr/sbin/sshd", "/etc/passwd", "/etc/shadow"]
            .iter()
            .map(PathBuf::from)
            .collect();
        assert_eq!(out.effective, expected);
        assert!(out.added.is_empty());
        assert!(out.disabled.is_empty());
        assert!(out.unknown_disable.is_empty());
        assert_eq!(out.defaults, DefaultsSource::Disk);
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
        let out = load_own(&v1, &verified(&local));

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

    /// External audit LLMR-016: with `fim-paths.v1` unreadable, FIM watches
    /// the shipped list built into the agent (it used to watch only the
    /// overlay's additions), and the load says so for the signed record.
    #[test]
    fn a_missing_v1_uses_the_built_in_list_and_says_so() {
        let dir = TempDir::new().unwrap();
        let out = load_watched_paths(&dir.path().join("missing.v1"), &Verified::Missing)
            .expect("a missing v1 is tolerated");
        assert!(matches!(out.defaults, DefaultsSource::BuiltIn(_)));
        assert!(out.effective.contains(&PathBuf::from("/etc/shadow")));
        assert!(out.effective.contains(&PathBuf::from("/etc/ld.so.preload")));
        assert!(out.added.is_empty());
        assert!(out.disabled.is_empty());
    }

    /// Tappa 10.5 D3: the SHIPPED `configs/fim-paths.v1`
    /// (install.sh drops it to /etc/northnarrow/) parses clean and
    /// includes the new D3 watch paths. A malformed default (e.g. a
    /// stray directive prefix) fails the build's test gate rather
    /// than at an operator's boot.
    #[test]
    fn shipped_fim_paths_v1_loads_clean_with_d3_paths() {
        let v1 = std::path::PathBuf::from(concat!(env!("NN_REPO_ROOT"), "/configs/fim-paths.v1"));
        // No overlay shipped (operator-curated) — exercise v1-only.
        let out = load_watched_paths(&v1, &Verified::Missing)
            .expect("shipped fim-paths.v1 must parse clean");
        for p in [
            "/etc/ld.so.preload",
            "/root/.gnupg",
            "/root/.password-store",
            "/usr/lib/x86_64-linux-gnu/security",
            "/root/.config/google-chrome/Default/Login Data",
        ] {
            assert!(
                out.effective.contains(&PathBuf::from(p)),
                "shipped fim-paths.v1 should watch {p} (D3)"
            );
        }
        assert_eq!(
            std::fs::read_to_string(&v1).unwrap(),
            BUILTIN_PATHS_V1,
            "the built-in copy is the shipped file"
        );
    }

    /// External audit LLMR-015: `fim-paths.v1` with a watched path taken
    /// out by hand (offline: the inode is protected while the agent runs)
    /// does not stop FIM watching it — the built-in list is watched and the
    /// edit reported.
    #[test]
    fn a_watched_path_removed_by_hand_is_still_watched() {
        let dir = TempDir::new().unwrap();
        let v1 = dir.path().join("fim-paths.v1");
        let edited: String = BUILTIN_PATHS_V1
            .lines()
            .filter(|l| l.trim() != "/etc/ld.so.preload")
            .map(|l| format!("{l}\n"))
            .collect();
        assert_ne!(edited, BUILTIN_PATHS_V1);
        std::fs::write(&v1, &edited).unwrap();
        let out = load_watched_paths(&v1, &Verified::Missing).unwrap();
        assert!(out.effective.contains(&PathBuf::from("/etc/ld.so.preload")));
        assert!(matches!(out.defaults, DefaultsSource::Modified { .. }));
        std::fs::write(&v1, BUILTIN_PATHS_V1).unwrap();
        let out = load_watched_paths(&v1, &Verified::Missing).unwrap();
        assert_eq!(out.defaults, DefaultsSource::Disk);
    }

    /// C7 #4: a malformed v1 (relative path) is rejected up-front
    /// rather than silently registering a non-absolute path. The
    /// agent boot continues (load_watched_paths returns Err but
    /// the WARN-then-empty path in `load_watched_paths` keeps the
    /// agent up); this test confirms the inner `read_default_list`
    /// surfaces the diagnostic.
    #[test]
    fn read_default_list_skips_a_relative_path() {
        let dir = TempDir::new().unwrap();
        let v1 = dir.path().join("fim-paths.v1");
        std::fs::write(&v1, "relative/path/no-leading-slash\n").unwrap();
        // External audit FIMR-001: skipped and reported, not the whole list.
        assert!(read_default_list(&v1).unwrap().is_empty());
    }

    /// C7 #5: a v1 file that accidentally contains `+`/`-` prefixed
    /// lines (operator copied a `.local` template over `v1`): those lines
    /// are reported and skipped (external audit FIMR-001), the rest kept.
    #[test]
    fn read_default_list_skips_directive_prefixes() {
        let dir = TempDir::new().unwrap();
        let v1 = dir.path().join("fim-paths.v1");
        std::fs::write(&v1, "/usr/sbin/sshd\n+/oops/operator-overlay-syntax\n").unwrap();
        let set = read_default_list(&v1).unwrap();
        assert_eq!(
            set.into_iter().collect::<Vec<_>>(),
            vec![std::path::PathBuf::from("/usr/sbin/sshd")]
        );
    }

    /// External audit FIMR-001: one invalid line used to empty the whole
    /// default list — FIM watched nothing. Only that line is dropped now.
    #[test]
    fn one_invalid_line_drops_only_itself() {
        let dir = tempfile::TempDir::new().unwrap();
        let v1 = dir.path().join("fim-paths.v1");
        std::fs::write(&v1, "/etc/passwd\nrelative/path\n+/etc/x\n/etc/shadow\n").unwrap();
        let load = load_own(&v1, &Verified::Missing);
        let got: Vec<String> = load
            .effective
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        assert_eq!(
            got,
            vec!["/etc/passwd".to_string(), "/etc/shadow".to_string()]
        );
    }
}
