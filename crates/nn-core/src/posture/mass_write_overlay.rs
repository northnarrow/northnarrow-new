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
//! burst many writes per second. There is no `.v1` curated default; the
//! file is purely additive and OPTIONAL.
//!
//! ## What an entry may not cover (external audit POS-010, lab PR 198)
//!
//! A signed overlay only proves an administrator wrote it, not that the
//! entry is narrow: `/` or `/home` switched the ransomware arm off for the
//! whole host, and the load reported a count. An entry is now refused —
//! a WARN naming it and its line at load, an error naming it for
//! `nn-admin config overlay set` / `sign` — when, its repeated `/` folded,
//! it
//! - is `/`, or has a `.` or `..` component;
//! - is a top-level directory (`/home`, `/root`, `/srv`, `/var`, `/tmp`,
//!   `/media`, `/mnt`, `/data`, `/opt`, `/usr`, or any other): fewer
//!   than two components;
//! - is a whole user's tree: `/home/<user>` or `/run/user/<uid>`;
//! - covers a shared tree the arm counts on purpose: `/var/tmp`,
//!   `/dev/shm` (staging) and `/run/user` (see
//!   [`super::triggers::MASS_WRITE_CARVEOUT_PREFIXES`]).
//!
//! An entry without its final `/` is a name prefix where the posture
//! matches it (`/home/al` covers `/home/alice`), so it is judged as one:
//! `/var/t` covers `/var/tmp`. The accepted list is logged once, at WARN,
//! with the name-prefix entries apart.

use tracing::{info, warn};

use crate::config::overlay_auth::Verified;

/// Default deploy location of the optional mass-write carve-out
/// overlay. Missing file → empty list (no extra exemptions); the
/// hardcoded `MASS_WRITE_CARVEOUT_PREFIXES` still apply.
pub const DEFAULT_MASS_WRITE_OVERLAY: &str = "/etc/northnarrow/mass-write-carveout.local";

/// The top-level directories that hold the host's data and software,
/// named in a refusal (every top-level directory is refused).
const DATA_ROOTS: &[&str] = &[
    "home", "root", "srv", "var", "tmp", "media", "mnt", "data", "opt", "usr",
];

/// Parents one level below which a directory is a whole user's tree.
const PER_USER_PARENTS: &[&[&str]] = &[&["home"], &["run", "user"]];

/// Shared, world-writable trees the mass-write arm counts on purpose.
const SHARED_TREES: &[&[&str]] = &[&["var", "tmp"], &["dev", "shm"], &["run", "user"]];

/// One line of the overlay: `Ok(None)` for a blank or comment line,
/// `Ok(Some(entry))` for an accepted entry (repeated `/` folded), `Err`
/// with the reason, the entry named, for a refused one. The loader and
/// agent's `config::overlay_auth::validate_content` share it.
pub fn parse_line(raw: &str) -> Result<Option<String>, String> {
    let stripped = match raw.split_once('#') {
        Some((before, _comment)) => before,
        None => raw,
    };
    let trimmed = stripped.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if let Some(rest) = trimmed.strip_prefix('-') {
        return Err(format!(
            "`-{}`: the `-` directive has no effect in this overlay (no v1 default to disable)",
            rest.trim()
        ));
    }
    let entry = trimmed.strip_prefix('+').unwrap_or(trimmed).trim();
    if entry.is_empty() {
        return Err("empty entry after `+`".to_string());
    }
    if !entry.starts_with('/') {
        return Err(format!("`{entry}`: not an absolute path prefix"));
    }
    let folded = fold_slashes(entry);
    too_broad(&folded).map_err(|why| format!("`{entry}`: {why}"))?;
    Ok(Some(folded))
}

/// `entry` with every run of `/` folded into one (its final `/`, which
/// makes it a directory rather than a name prefix, kept).
fn fold_slashes(entry: &str) -> String {
    let mut out = String::with_capacity(entry.len());
    for c in entry.chars() {
        if c == '/' && out.ends_with('/') {
            continue;
        }
        out.push(c);
    }
    out
}

/// Why a folded entry covers too much, if it does.
fn too_broad(entry: &str) -> Result<(), String> {
    let comps: Vec<&str> = entry.split('/').filter(|c| !c.is_empty()).collect();
    if comps.iter().any(|c| *c == "." || *c == "..") {
        return Err("a `.` or `..` component (write the directory itself)".to_string());
    }
    // Without its final `/` the posture matches the entry as a string
    // prefix: its last component is a name prefix.
    let name_prefix = !entry.ends_with('/');
    let Some((last, parent)) = comps.split_last() else {
        return Err("`/` covers the whole filesystem".to_string());
    };
    if parent.is_empty() {
        return Err(match DATA_ROOTS.iter().find(|r| **r == *last) {
            Some(r) => format!("`/{r}` is a data root — name a directory below it"),
            None => "a top-level directory — name one at least two levels deep".to_string(),
        });
    }
    for tree in SHARED_TREES {
        if covers(&comps, name_prefix, tree) {
            return Err(format!(
                "covers `/{}`, a shared tree the mass-write arm counts on purpose",
                tree.join("/")
            ));
        }
    }
    for p in PER_USER_PARENTS {
        if parent == *p {
            return Err(format!(
                "a whole user's tree (`/{}/<user>`{})",
                p.join("/"),
                if name_prefix {
                    ", or several of them"
                } else {
                    ""
                }
            ));
        }
    }
    Ok(())
}

/// Does an entry of components `comps` (its last a name prefix when
/// `name_prefix`) cover the whole of `tree`?
fn covers(comps: &[&str], name_prefix: bool, tree: &[&str]) -> bool {
    let Some((last, parent)) = comps.split_last() else {
        return true;
    };
    if comps.len() > tree.len() || parent != &tree[..parent.len()] {
        return false;
    }
    let at = tree[parent.len()];
    at == *last || (name_prefix && at.starts_with(last))
}

/// Accepted entries, and the refused lines (1-based number, reason).
pub fn parse_text(text: &str) -> (Vec<String>, Vec<(usize, String)>) {
    let mut accepted = Vec::new();
    let mut refused = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        match parse_line(raw) {
            Ok(Some(e)) => accepted.push(e),
            Ok(None) => {}
            Err(why) => refused.push((i + 1, why)),
        }
    }
    (accepted, refused)
}

/// Parse the overlay, as the signed-overlay gate verified it (external
/// audit LLMR-013: its text, never the path read again). None → an empty
/// Vec — this is purely additive and not boot-critical.
///
/// Accepted line shapes (after stripping `#` comments and trimming):
/// - `+/absolute/prefix`  — add prefix
/// - `/absolute/prefix`   — add prefix (bare path is treated as add,
///   same convenience as fim-paths.local)
/// - `-…`                 — REJECTED here: there is no curated v1
///   list to disable from.
///
/// A refused line (relative, empty, `-`, or too broad: see the module
/// docs) is a WARN with `path:lineno` and the reason, and is dropped; the
/// rest of the file applies. A non-empty result is one WARN listing it.
pub fn load_mass_write_carveout_extras(local: &Verified) -> Vec<String> {
    let (Some(body), Some(local_path)) = (local.text(), local.source()) else {
        return Vec::new();
    };
    let (out, refused) = parse_text(body);
    for (lineno, reason) in &refused {
        warn!(
            path = %local_path.display(),
            lineno,
            reason = %reason,
            "mass-write overlay: entry REFUSED — not applied"
        );
    }
    if out.is_empty() {
        info!(
            path = %local_path.display(),
            refused = refused.len(),
            "mass-write overlay: load complete, no carve-out added"
        );
    } else {
        let name_prefixes: Vec<&String> = out.iter().filter(|e| !e.ends_with('/')).collect();
        warn!(
            path = %local_path.display(),
            carveouts = ?out,
            name_prefixes = ?name_prefixes,
            refused = refused.len(),
            "mass-write overlay: ransomware-shape detection is OFF under these carve-outs"
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overlay(body: &str) -> Verified {
        Verified::Content {
            path: DEFAULT_MASS_WRITE_OVERLAY.into(),
            text: body.to_string(),
        }
    }

    #[test]
    fn missing_file_returns_empty() {
        assert!(load_mass_write_carveout_extras(&Verified::Missing).is_empty());
        assert!(load_mass_write_carveout_extras(&Verified::Refused).is_empty());
    }

    #[test]
    fn parses_plus_and_bare_lines() {
        let out = load_mass_write_carveout_extras(&overlay(
            "# header comment\n\
             +/home/alice/.claude/\n\
             /tmp/claude-                  # bare path treated as add\n\
             \n\
             +/var/lib/devtool/cache/\n",
        ));
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
        let out = load_mass_write_carveout_extras(&overlay("+not-absolute\n+/ok/dir/\n"));
        assert_eq!(out, vec!["/ok/dir/".to_string()]);
    }

    #[test]
    fn minus_directive_is_ignored_and_warned() {
        let out = load_mass_write_carveout_extras(&overlay("-/sys/\n+/keep/me/\n"));
        // `-` lines are dropped (no v1 to disable from). `+` line stays.
        assert_eq!(out, vec!["/keep/me/".to_string()]);
    }

    /// External audit POS-010: `/`, a data root and a whole home switched
    /// the ransomware arm off where it matters; only the narrow entry stays.
    #[test]
    fn root_and_data_roots_are_rejected() {
        let out = load_mass_write_carveout_extras(&overlay(
            "/\n+/home\n+/home/alice\n+/var/lib/devtool/cache/\n",
        ));
        assert_eq!(out, vec!["/var/lib/devtool/cache/".to_string()]);
    }

    /// Each refusal names the entry and says why; the line number is the
    /// file's.
    #[test]
    fn too_broad_entries_are_refused_by_name() {
        let refused = |body: &str| {
            let (out, refused) = parse_text(body);
            assert!(out.is_empty(), "{body:?} accepted {out:?}");
            assert_eq!(refused.len(), 1, "{body:?}: {refused:?}");
            refused[0].clone()
        };
        let cases: &[(&str, &str)] = &[
            ("/", "whole filesystem"),
            ("//", "whole filesystem"),
            ("+/home/", "data root"),
            ("/var", "data root"),
            ("/tmp/", "data root"),
            ("/usr", "data root"),
            ("/data", "data root"),
            ("/etc", "top-level directory"),
            // a name prefix of a top-level directory is one too
            ("/ho", "top-level directory"),
            ("/home/alice/", "whole user's tree"),
            ("/home//bob", "whole user's tree"),
            ("/home/al", "or several of them"),
            ("/run/user/1000/", "whole user's tree"),
            ("/var/tmp/", "`/var/tmp`"),
            ("/var/t", "`/var/tmp`"),
            ("/dev/shm", "`/dev/shm`"),
            ("/run/user", "`/run/user`"),
            ("/var/lib/../../home/", "`..`"),
            ("/srv/./build/", "`..`"),
        ];
        for (body, why) in cases {
            let (lineno, msg) = refused(&format!("# header\n{body}\n"));
            assert_eq!(lineno, 2, "{body}");
            let entry = body.strip_prefix('+').unwrap_or(body);
            assert!(msg.contains(&format!("`{entry}`")), "{body}: {msg}");
            assert!(msg.contains(why), "{body}: {msg}");
        }
    }

    /// What legitimate overlays carry still loads: the BUG-017 dev-host
    /// overlay, a build tree, a tool directory below a shared tree.
    #[test]
    fn narrow_entries_still_load() {
        let (out, refused) = parse_text(
            "+/home/alice/.claude/\n\
             +/tmp/claude-\n\
             +/srv/build/\n\
             +/root/.cache/tool/\n\
             +/run/user/1000/tool/\n\
             +/var/tmp/ci-cache/\n\
             +/var/lib//devtool/cache/\n",
        );
        assert!(refused.is_empty(), "{refused:?}");
        assert_eq!(
            out,
            vec![
                "/home/alice/.claude/",
                "/tmp/claude-",
                "/srv/build/",
                "/root/.cache/tool/",
                "/run/user/1000/tool/",
                "/var/tmp/ci-cache/",
                // repeated `/` folded: the posture matches kernel paths
                "/var/lib/devtool/cache/",
            ]
        );
    }
}
