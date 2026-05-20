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

use anyhow::{anyhow, Context, Result};
use tracing::{info, warn};

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
pub fn load_watched_paths(
    v1_path: &Path,
    local_path: &Path,
) -> Result<WatchedPathsLoad> {
    let defaults = match read_default_list(v1_path) {
        Ok(set) => set,
        Err(e) => {
            warn!(
                error = %e,
                path = %v1_path.display(),
                "fim paths-config: default v1 list missing or unreadable — no defaults this boot"
            );
            BTreeSet::new()
        }
    };
    let (adds, disables) = match read_local_overlay(local_path) {
        Ok(pair) => pair,
        Err(e) => {
            warn!(
                error = %e,
                path = %local_path.display(),
                "fim paths-config: operator overlay file unreadable — \
                 ignoring local overlay this boot"
            );
            (BTreeSet::new(), BTreeSet::new())
        }
    };

    // Q7 lock-in: per-disabled WARN at every boot so operators
    // can't silently hide a regression.
    let mut disabled = BTreeSet::new();
    let mut unknown_disable = BTreeSet::new();
    for d in &disables {
        if defaults.contains(d) {
            disabled.insert(d.clone());
            warn!(
                path = %d.display(),
                "fim paths-config: default path disabled by operator config (§13 Q7)"
            );
        } else {
            unknown_disable.insert(d.clone());
            warn!(
                path = %d.display(),
                "fim paths-config: operator `disable:` targets a path not in the v1 default \
                 list — no-op (check spelling)"
            );
        }
    }

    let mut effective: BTreeSet<PathBuf> = defaults
        .iter()
        .filter(|p| !disabled.contains(*p))
        .cloned()
        .collect();
    for a in &adds {
        effective.insert(a.clone());
    }

    info!(
        defaults = defaults.len(),
        added = adds.len(),
        disabled = disabled.len(),
        unknown_disable = unknown_disable.len(),
        effective = effective.len(),
        "fim paths-config: watched-paths load complete"
    );

    Ok(WatchedPathsLoad {
        effective,
        added: adds,
        disabled,
        unknown_disable,
    })
}

/// Read the curated default list. Missing → `NotFound`; the caller
/// in [`load_watched_paths`] turns that into a WARN + empty set.
fn read_default_list(path: &Path) -> Result<BTreeSet<PathBuf>> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("reading default paths file {}", path.display()))?;
    let mut set = BTreeSet::new();
    for (lineno, raw) in body.lines().enumerate() {
        let trimmed = strip_comment(raw).trim();
        if trimmed.is_empty() {
            continue;
        }
        // Defensive: a default list shouldn't have +/- prefixes; if
        // someone copies a `.local` template over `v1` we surface it.
        if trimmed.starts_with('+') || trimmed.starts_with('-') {
            return Err(anyhow!(
                "{}:{}: default list must not use +/- prefixes (those are local-overlay only)",
                path.display(),
                lineno + 1
            ));
        }
        if !trimmed.starts_with('/') {
            return Err(anyhow!(
                "{}:{}: paths must be absolute (start with `/`), got `{}`",
                path.display(),
                lineno + 1,
                trimmed
            ));
        }
        set.insert(PathBuf::from(trimmed));
    }
    Ok(set)
}

/// Read the operator overlay file. Returns `(adds, disables)`.
/// Missing → `NotFound`; caller turns that into a no-overlay
/// outcome.
fn read_local_overlay(path: &Path) -> Result<(BTreeSet<PathBuf>, BTreeSet<PathBuf>)> {
    let body = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
        Err(e) => {
            return Err(anyhow!(e)
                .context(format!("reading operator overlay {}", path.display())))
        }
    };
    let mut adds = BTreeSet::new();
    let mut disables = BTreeSet::new();
    for (lineno, raw) in body.lines().enumerate() {
        let trimmed = strip_comment(raw).trim();
        if trimmed.is_empty() {
            continue;
        }
        let (directive, rest) = split_directive(trimmed);
        if !rest.starts_with('/') {
            return Err(anyhow!(
                "{}:{}: paths must be absolute (start with `/`), got `{}`",
                path.display(),
                lineno + 1,
                rest
            ));
        }
        let pb = PathBuf::from(rest);
        match directive {
            Directive::Add => {
                adds.insert(pb);
            }
            Directive::Disable => {
                disables.insert(pb);
            }
        }
    }
    Ok((adds, disables))
}

#[derive(Debug, Clone, Copy)]
enum Directive {
    Add,
    Disable,
}

fn split_directive(s: &str) -> (Directive, &str) {
    if let Some(rest) = s.strip_prefix('+') {
        (Directive::Add, rest.trim_start())
    } else if let Some(rest) = s.strip_prefix('-') {
        (Directive::Disable, rest.trim_start())
    } else {
        (Directive::Add, s)
    }
}

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(idx) => &line[..idx],
        None => line,
    }
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
        let expected: BTreeSet<PathBuf> = [
            "/usr/sbin/sshd",
            "/etc/passwd",
            "/etc/shadow",
        ]
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
