//! BUG-017 P-8 — operator-tunable mass-write path-prefix carve-out.
//!
//! The mass-write arm of [`super::triggers::confirmed_intrusion`]
//! exempts a fixed set of kernel-RPC pseudo-FS prefixes
//! ([`super::triggers::MASS_WRITE_CARVEOUT_PREFIXES`]) — /sys, /proc,
//! /run/systemd, /run/log/journal. Those are universal kernel control
//! surfaces and never data writes.
//!
//! Operators can layer additional trusted-heavy-IO path prefixes on
//! top by dropping `/etc/northnarrow/mass-write-carveout.local`.
//! Schema mirrors the other operator overlays (fim-paths.local,
//! process-comm-allowlist.local): one entry per line, `#` for
//! comments, blank lines ignored, optional `+` directive prefix.
//!
//! **Security note**: every prefix listed here suppresses
//! ransomware-shape detection inside that path tree. Use sparingly.
//! Typical entries are dev-tooling state directories (e.g. agent
//! transcript stores in `/home/<user>/.claude/`) that legitimately
//! burst many writes per second. Do NOT add `/home`, `/var`, or
//! `/tmp` wholesale — those are canonical ransomware staging
//! targets. There is no `.v1` curated default; the file is purely
//! additive and OPTIONAL.

use std::path::Path;

use tracing::{info, warn};

/// Default deploy location of the optional mass-write carve-out
/// overlay. Missing file → empty list (no extra exemptions); the
/// hardcoded `MASS_WRITE_CARVEOUT_PREFIXES` still apply.
pub const DEFAULT_MASS_WRITE_OVERLAY: &str = "/etc/northnarrow/mass-write-carveout.local";

/// Parse the overlay file. Returns an empty Vec if the file is
/// missing or unreadable (with a WARN on parse failure but never an
/// error — this is purely additive and not boot-critical).
///
/// Accepted line shapes (after stripping `#` comments and trimming):
/// - `+/absolute/prefix`  — add prefix
/// - `/absolute/prefix`   — add prefix (bare path is treated as add,
///                           same convenience as fim-paths.local)
/// - `-…`                 — REJECTED here: there is no curated v1
///                           list to disable from. A `-` line WARNs
///                           and is dropped.
///
/// Invalid entries (relative paths, empty, `-` directive) are
/// surfaced via WARN with `path:lineno`.
pub fn load_mass_write_carveout_extras(local_path: &Path) -> Vec<String> {
    let body = match std::fs::read_to_string(local_path) {
        Ok(s) => s,
        Err(e) => {
            // Missing file is the common case on operator hosts
            // (no dev tooling to exempt). Only WARN on a non-NotFound
            // error.
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!(
                    error = %e,
                    path = %local_path.display(),
                    "mass-write overlay: read failed — ignoring overlay this boot"
                );
            }
            return Vec::new();
        }
    };
    let mut out: Vec<String> = Vec::new();
    for (lineno, raw) in body.lines().enumerate() {
        let lineno = lineno + 1; // human-friendly 1-indexed
        let stripped = match raw.split_once('#') {
            Some((before, _comment)) => before,
            None => raw,
        };
        let trimmed = stripped.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix('-') {
            warn!(
                path = %local_path.display(),
                lineno,
                entry = %rest.trim(),
                "mass-write overlay: `-` directive has no effect (no v1 default to disable) — ignored"
            );
            continue;
        }
        let entry = trimmed.strip_prefix('+').unwrap_or(trimmed).trim();
        if entry.is_empty() {
            warn!(
                path = %local_path.display(),
                lineno,
                "mass-write overlay: empty entry after directive — ignored"
            );
            continue;
        }
        if !entry.starts_with('/') {
            warn!(
                path = %local_path.display(),
                lineno,
                entry = %entry,
                "mass-write overlay: entry must be an absolute path prefix — ignored"
            );
            continue;
        }
        out.push(entry.to_string());
    }
    info!(
        path = %local_path.display(),
        added = out.len(),
        "mass-write overlay: load complete"
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_overlay(dir: &Path, body: &str) -> std::path::PathBuf {
        let p = dir.join("mass-write-carveout.local");
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn missing_file_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("does-not-exist");
        assert!(load_mass_write_carveout_extras(&p).is_empty());
    }

    #[test]
    fn parses_plus_and_bare_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_overlay(
            tmp.path(),
            "# header comment\n\
             +/home/alice/.claude/\n\
             /tmp/claude-                  # bare path treated as add\n\
             \n\
             +/var/lib/devtool/cache/\n",
        );
        let out = load_mass_write_carveout_extras(&p);
        assert_eq!(
            out,
            vec![
                "/home/alice/.claude/".to_string(),
                "/tmp/claude-".to_string(),
                "/var/lib/devtool/cache/".to_string(),
            ]
        );
    }

    #[test]
    fn relative_path_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_overlay(tmp.path(), "+not-absolute\n+/ok/\n");
        let out = load_mass_write_carveout_extras(&p);
        assert_eq!(out, vec!["/ok/".to_string()]);
    }

    #[test]
    fn minus_directive_is_ignored_and_warned() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_overlay(tmp.path(), "-/sys/\n+/keep/\n");
        let out = load_mass_write_carveout_extras(&p);
        // `-` lines are dropped (no v1 to disable from). `+` line stays.
        assert_eq!(out, vec!["/keep/".to_string()]);
    }
}
