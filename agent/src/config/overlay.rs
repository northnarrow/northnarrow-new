//! Tappa 10.5 (D1) — generic flat-list `.v1` + `.local` overlay
//! loader.
//!
//! This is the directive-parsing core extracted verbatim from the
//! Tappa 9 C7 FIM watched-paths loader (`fim/paths_config.rs`) so
//! the process + network rule families (Tappa 10.5 §3.6 / §13 Q3)
//! reuse one parser instead of copy-pasting it. The FIM loader is
//! now a thin typed wrapper over [`load_flat_list`] (path-typed +
//! absolute-path validation); the comm-allowlist families wrap it
//! with a bare-token validator (`config/comm_allowlist.rs`).
//!
//! ## File shapes (identical to Tappa 9 C7 `fim-paths`)
//!
//! - **`.v1` default** — one bare entry per line, `#` comments,
//!   blank lines ignored, NO directives. A `+`/`-` prefix in a
//!   `.v1` file is a hard error (an operator copied a `.local`
//!   template over the default), surfaced at boot.
//! - **`.local` overlay** (OPTIONAL) — `+entry` to add, `-entry`
//!   to disable a default, bare `entry` treated as add (so the
//!   file can be a plain extension list). `#` comments, blanks
//!   ignored.
//!
//! ## Boot-time WARN lock-in (Tappa 9 §13 Q7, preserved)
//!
//! Every default entry that the `.local` overlay disables emits a
//! per-entry WARN at load. An operator can't silently hide a
//! detection regression. `-entry` lines targeting a non-default
//! entry are surfaced separately as `unknown_disable` (no-op +
//! its own WARN, in case of a typo).

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use tracing::{info, warn};

/// Validates a single entry AFTER directive stripping. Returns a
/// human diagnostic on rejection; the loader wraps it with the
/// `path:lineno` context so every family gets uniform error
/// framing. Typed wrappers supply the family-specific shape rule
/// (FIM: absolute path; comm lists: bare process token).
pub type EntryValidator<'a> = &'a dyn Fn(&str) -> Result<()>;

/// Outcome of [`load_flat_list`]. `effective` is the merged set the
/// caller acts on; the other fields surface operator visibility
/// (boot logs + status CLIs). Generic over `String` entries — typed
/// wrappers map these into their domain type (e.g. `PathBuf`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OverlayLoad {
    /// Final merged set: defaults minus disables plus adds.
    /// `BTreeSet` for deterministic iteration (audit-grade boot
    /// logs benefit from stable ordering).
    pub effective: BTreeSet<String>,
    /// Entries added by the overlay's `+` / bare-entry lines.
    pub added: BTreeSet<String>,
    /// Entries the overlay disabled with a `-` line AND that were
    /// actually present in the default list.
    pub disabled: BTreeSet<String>,
    /// `-` lines whose target was not in the default list — a no-op,
    /// surfaced so operators don't think they disabled something
    /// they in fact mistyped.
    pub unknown_disable: BTreeSet<String>,
}

/// Load and merge a `.v1` default and a `.local` overlay. Either or
/// both being missing is tolerated: a missing `.v1` yields empty
/// defaults plus a WARN, and a missing `.local` means no overlay.
/// Errors propagate only on read/parse failure of a file that DID
/// exist.
///
/// `label` prefixes every log line (e.g. `"fim paths-config"` or
/// `"process-comm-allowlist"`) so boot logs name the family.
pub fn load_flat_list(
    label: &str,
    v1_path: &Path,
    local_path: &Path,
    validate: EntryValidator<'_>,
) -> Result<OverlayLoad> {
    let defaults = match parse_default_list(v1_path, validate) {
        Ok(set) => set,
        Err(e) => {
            warn!(
                error = %e,
                path = %v1_path.display(),
                "{label}: default v1 list missing or unreadable — no defaults this boot"
            );
            BTreeSet::new()
        }
    };
    let (adds, disables) = match parse_local_overlay(local_path, validate) {
        Ok(pair) => pair,
        Err(e) => {
            warn!(
                error = %e,
                path = %local_path.display(),
                "{label}: operator overlay file unreadable — ignoring local overlay this boot"
            );
            (BTreeSet::new(), BTreeSet::new())
        }
    };

    // Q7 lock-in: per-disabled WARN at every boot so operators can't
    // silently hide a regression.
    let mut disabled = BTreeSet::new();
    let mut unknown_disable = BTreeSet::new();
    for d in &disables {
        if defaults.contains(d) {
            disabled.insert(d.clone());
            warn!(
                entry = %d,
                "{label}: default entry disabled by operator config (§13 Q7)"
            );
        } else {
            unknown_disable.insert(d.clone());
            warn!(
                entry = %d,
                "{label}: operator disable targets an entry not in the v1 default list — \
                 no-op (check spelling)"
            );
        }
    }

    let mut effective: BTreeSet<String> = defaults
        .iter()
        .filter(|e| !disabled.contains(*e))
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
        "{label}: load complete"
    );

    Ok(OverlayLoad {
        effective,
        added: adds,
        disabled,
        unknown_disable,
    })
}

/// Parse a `.v1` default list. Missing file → `Err` (the caller in
/// [`load_flat_list`] turns that into a WARN + empty set). Rejects
/// `+`/`-` prefixes (those are `.local`-only). Each entry is run
/// through `validate`.
pub fn parse_default_list(path: &Path, validate: EntryValidator<'_>) -> Result<BTreeSet<String>> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("reading default list {}", path.display()))?;
    let mut set = BTreeSet::new();
    for (lineno, raw) in body.lines().enumerate() {
        let trimmed = strip_comment(raw).trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('+') || trimmed.starts_with('-') {
            return Err(anyhow!(
                "{}:{}: default list must not use +/- prefixes (those are local-overlay only)",
                path.display(),
                lineno + 1
            ));
        }
        validate(trimmed).map_err(|e| anyhow!("{}:{}: {}", path.display(), lineno + 1, e))?;
        set.insert(trimmed.to_string());
    }
    Ok(set)
}

/// Parse a `.local` overlay. Returns `(adds, disables)`. Missing
/// file → empty pair (no overlay). Each entry is run through
/// `validate` after directive stripping.
fn parse_local_overlay(
    path: &Path,
    validate: EntryValidator<'_>,
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let body = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
        Err(e) => {
            return Err(anyhow!(e).context(format!("reading operator overlay {}", path.display())))
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
        validate(rest).map_err(|e| anyhow!("{}:{}: {}", path.display(), lineno + 1, e))?;
        let entry = rest.to_string();
        match directive {
            Directive::Add => {
                adds.insert(entry);
            }
            Directive::Disable => {
                disables.insert(entry);
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

    /// A validator that accepts any non-empty token — keeps the
    /// loader tests focused on the overlay mechanics, not on a
    /// family's shape rule (those are covered by the typed-wrapper
    /// tests in `comm_allowlist.rs` + `fim/paths_config.rs`).
    fn accept_any(entry: &str) -> Result<()> {
        if entry.is_empty() {
            return Err(anyhow!("empty entry"));
        }
        Ok(())
    }

    /// D1: a `.v1`-only file with no overlay yields exactly the
    /// bare entries as `effective`; the other fields are empty.
    #[test]
    fn allowlist_loader_parses_bare_flat_list() {
        let dir = TempDir::new().unwrap();
        let v1 = dir.path().join("comm.v1");
        let local = dir.path().join("comm.local");
        std::fs::write(
            &v1,
            "# header comment\n\
             sshd\n\
             nginx\n\
             \n\
             curl   # inline comment\n",
        )
        .unwrap();
        // local ABSENT — the no-overlay case.
        let out = load_flat_list("test-allowlist", &v1, &local, &accept_any).expect("load");
        let expected: BTreeSet<String> = ["sshd", "nginx", "curl"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(out.effective, expected);
        assert!(out.added.is_empty());
        assert!(out.disabled.is_empty());
        assert!(out.unknown_disable.is_empty());
    }

    /// D1: overlay with both add (`+`/bare) and disable (`-`) lines.
    /// Verifies the merge: defaults minus disables plus adds.
    #[test]
    fn allowlist_loader_applies_local_overlay_add_disable() {
        let dir = TempDir::new().unwrap();
        let v1 = dir.path().join("comm.v1");
        let local = dir.path().join("comm.local");
        std::fs::write(&v1, "sshd\nnginx\ncurl\n").unwrap();
        std::fs::write(
            &local,
            "# operator overlay\n\
             +my-deploy-tool\n\
             ci-runner          # bare entry = add\n\
             -nginx\n",
        )
        .unwrap();
        let out = load_flat_list("test-allowlist", &v1, &local, &accept_any).expect("load");

        let expected: BTreeSet<String> = ["sshd", "curl", "my-deploy-tool", "ci-runner"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(out.effective, expected);
        assert!(out.added.contains("my-deploy-tool"));
        assert!(out.added.contains("ci-runner"));
        assert!(out.disabled.contains("nginx"));
        assert!(out.unknown_disable.is_empty());
    }

    /// D1: a `-` line targeting an entry not present in the `.v1`
    /// default list is a no-op surfaced as `unknown_disable` (not
    /// `disabled`), so a typo'd disable is operator-visible.
    #[test]
    fn allowlist_loader_warns_on_unknown_disable() {
        let dir = TempDir::new().unwrap();
        let v1 = dir.path().join("comm.v1");
        let local = dir.path().join("comm.local");
        std::fs::write(&v1, "sshd\nnginx\n").unwrap();
        std::fs::write(&local, "-not-a-default-comm\n").unwrap();
        let out = load_flat_list("test-allowlist", &v1, &local, &accept_any).expect("load");

        // Defaults unchanged (the disable hit nothing).
        let expected: BTreeSet<String> = ["sshd", "nginx"].iter().map(|s| s.to_string()).collect();
        assert_eq!(out.effective, expected);
        assert!(out.disabled.is_empty());
        assert!(out.unknown_disable.contains("not-a-default-comm"));
    }

    /// D1: both files missing → empty load (WARN, not error), so a
    /// test agent or a host with no config files still boots.
    #[test]
    fn allowlist_loader_both_missing_returns_empty() {
        let dir = TempDir::new().unwrap();
        let out = load_flat_list(
            "test-allowlist",
            &dir.path().join("missing.v1"),
            &dir.path().join("missing.local"),
            &accept_any,
        )
        .expect("missing files tolerated");
        assert!(out.effective.is_empty());
    }

    /// D1: a `.v1` carrying a `+`/`-` directive (a `.local` template
    /// copied over the default) is rejected up-front so the install
    /// error surfaces at boot.
    #[test]
    fn parse_default_list_rejects_directive_prefixes() {
        let dir = TempDir::new().unwrap();
        let v1 = dir.path().join("comm.v1");
        std::fs::write(&v1, "sshd\n+oops-overlay-syntax\n").unwrap();
        let err = parse_default_list(&v1, &accept_any).expect_err("v1 must reject +/- prefixes");
        assert!(
            err.to_string().contains("local-overlay only"),
            "expected directive-prefix diagnostic, got: {err}"
        );
    }
}
