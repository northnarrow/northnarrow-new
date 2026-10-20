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
//!   template over the default), surfaced at boot. It is the shipped
//!   list, not operator configuration: the agent applies the copy it was
//!   built with, and the file only when it is that copy
//!   ([`load_defaults`], external audit LLMR-015).
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
use tracing::{error, info, warn};

use crate::config::overlay_auth::{content_sha256, read_overlay, Verified, ALLOW_UNSIGNED_ENV};

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
    /// Where the defaults came from (external audit LLMR-016).
    pub defaults: DefaultsSource,
}

/// Where a list's defaults came from (external audit LLMR-016, LLMR-015).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum DefaultsSource {
    /// The `.v1` file on disk, which is the copy built into the agent byte
    /// for byte.
    #[default]
    Disk,
    /// The copy built into the agent: the file could not be read (why).
    /// The caller records it ([`crate::config::overlay_auth::OverlayGate::report_default_unavailable`]).
    BuiltIn(String),
    /// The copy built into the agent: the file on disk is the list an
    /// earlier release shipped (its SHA-256), which `install.sh` replaces.
    /// A WARN, no record: the content in force is the shipped one.
    Superseded { sha256: String },
    /// The file on disk is no list NorthNarrow shipped — edited by hand.
    /// The copy built into the agent is in force, unless the unsigned
    /// configuration escape hatch is set (`loaded_anyway`: the file was
    /// applied). The caller records it
    /// ([`crate::config::overlay_auth::OverlayGate::report_default_modified`]).
    Modified {
        sha256: String,
        builtin_sha256: String,
        loaded_anyway: bool,
    },
}

/// A list's shipped defaults (external audit LLMR-015, NN-AUD-327): the
/// copy built into the agent — the current release's `configs/<list>.v1` —
/// and the SHA-256 (hex) of every copy an earlier release shipped. The
/// `.v1` files are not operator configuration: an operator tunes a list
/// through its signed `.local` overlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shipped<'a> {
    pub builtin: &'a str,
    pub earlier_sha256: &'a [&'a str],
}

impl<'a> Shipped<'a> {
    pub const fn new(builtin: &'a str, earlier_sha256: &'a [&'a str]) -> Self {
        Self {
            builtin,
            earlier_sha256,
        }
    }

    /// SHA-256 (hex) of the built-in copy.
    pub fn builtin_sha256(&self) -> String {
        hex::encode(content_sha256(self.builtin.as_bytes()))
    }
}

/// The defaults of a list (external audit LLMR-016, LLMR-015):
///
/// - the `.v1` on disk is the copy the agent was built with → used;
/// - it is the copy an earlier release shipped → the built-in copy, a WARN
///   (an upgrade that did not run `install.sh`; it replaces the file);
/// - it is anything else (an offline edit: an exemption added, a watched
///   path or a blocked range removed) → the built-in copy, an ERROR, and
///   [`DefaultsSource::Modified`] for the signed record. With
///   `NN_OVERLAY_ALLOW_UNSIGNED=1` (the escape hatch of the unsigned
///   overlays, itself a reported weakening) the file is applied anyway,
///   still reported;
/// - it cannot be read — missing, a symbolic link, a FIFO, larger than an
///   overlay may be — → the built-in copy, an ERROR (a missing
///   `fim-paths.v1` used to leave FIM watching only the overlay's
///   additions, with a WARN).
///
/// The file is read like an overlay ([`read_overlay`]): once, without
/// following a link, without blocking on a FIFO, at most 4 MiB. It used to
/// be applied as it was, and `install.sh` never replaced it, so a host kept
/// the lists of its first install (NET-011, lab PR 78: a KillProcessTree
/// rule on CGNAT and VPN ranges) and an offline edit took effect silently.
pub fn load_defaults<T>(
    label: &str,
    v1_path: &Path,
    shipped: Shipped<'_>,
    parse: impl Fn(&str, &str) -> T,
) -> (T, DefaultsSource) {
    let allow_modified = std::env::var(ALLOW_UNSIGNED_ENV).is_ok_and(|v| v == "1");
    load_defaults_with(label, v1_path, shipped, allow_modified, true, parse)
}

/// Lab PR 225: a shipped list with no operator overlay (`security-tools.v1`)
/// — pinned to the agent's built-in copy. As [`load_defaults`], except that a
/// modified file is never applied, not even under `NN_OVERLAY_ALLOW_UNSIGNED`
/// (there is no signed way to tune such a list, so its file is no
/// configuration), and the message points to no overlay. The file is not
/// signed: it is compared byte for byte with the built-in copy.
pub fn load_pinned_defaults<T>(
    label: &str,
    v1_path: &Path,
    shipped: Shipped<'_>,
    parse: impl Fn(&str, &str) -> T,
) -> (T, DefaultsSource) {
    load_defaults_with(label, v1_path, shipped, false, false, parse)
}

/// [`load_defaults`] with the escape hatch given, and whether the list has
/// a signed `.local` overlay to point the operator to.
fn load_defaults_with<T>(
    label: &str,
    v1_path: &Path,
    shipped: Shipped<'_>,
    allow_modified: bool,
    has_overlay: bool,
    parse: impl Fn(&str, &str) -> T,
) -> (T, DefaultsSource) {
    let built_in = |source: DefaultsSource| {
        (
            parse(&format!("{label} (built in)"), shipped.builtin),
            source,
        )
    };
    let bytes = match read_overlay(v1_path) {
        Ok(b) => b,
        Err(e) => {
            error!(
                error = %e,
                path = %v1_path.display(),
                "{label}: default list unreadable — the copy built into the agent is in force"
            );
            return built_in(DefaultsSource::BuiltIn(e.to_string()));
        }
    };
    if bytes == shipped.builtin.as_bytes() {
        return (
            parse(&v1_path.display().to_string(), shipped.builtin),
            DefaultsSource::Disk,
        );
    }
    let sha256 = hex::encode(content_sha256(&bytes));
    if shipped.earlier_sha256.contains(&sha256.as_str()) {
        warn!(
            path = %v1_path.display(),
            sha256 = %sha256,
            "{label}: the default list on disk is the one an earlier release shipped — the copy \
             built into the agent is in force (`install.sh --upgrade` replaces the file)"
        );
        return built_in(DefaultsSource::Superseded { sha256 });
    }
    let builtin_sha256 = shipped.builtin_sha256();
    if allow_modified {
        if let Ok(text) = std::str::from_utf8(&bytes) {
            error!(
                path = %v1_path.display(),
                sha256 = %sha256,
                builtin_sha256 = %builtin_sha256,
                "{label}: DEFAULT LIST MODIFIED — no list NorthNarrow shipped, applied anyway: \
                 {ALLOW_UNSIGNED_ENV}=1 is set"
            );
            return (
                parse(&v1_path.display().to_string(), text),
                DefaultsSource::Modified {
                    sha256,
                    builtin_sha256,
                    loaded_anyway: true,
                },
            );
        }
    }
    let hint = if has_overlay {
        "Tune the list through its signed `.local` overlay (`nn-admin config overlay set`); \
         `install.sh --upgrade` keeps the file as `.v1.operator` and installs the shipped one"
    } else {
        "This list has no operator overlay: the copy built into the agent is the list, the \
         file only mirrors it; `install.sh --upgrade` keeps the file as `.v1.operator` and \
         installs the shipped one"
    };
    error!(
        path = %v1_path.display(),
        sha256 = %sha256,
        builtin_sha256 = %builtin_sha256,
        "{label}: DEFAULT LIST MODIFIED — the file is no list NorthNarrow shipped (edited by hand?): \
         not applied, the copy built into the agent is in force. {hint}"
    );
    built_in(DefaultsSource::Modified {
        sha256,
        builtin_sha256,
        loaded_anyway: false,
    })
}

/// Load and merge a `.v1` default and a `.local` overlay. The defaults are
/// the shipped ones ([`load_defaults`]: the `.v1` when it is the built-in
/// copy, else that copy — [`OverlayLoad::defaults`] says which and why);
/// `local` is the overlay as the signed-overlay gate verified it — its
/// text, never a path to read again (external audit LLMR-013).
///
/// `label` prefixes every log line (e.g. `"fim paths-config"` or
/// `"process-comm-allowlist"`) so boot logs name the family.
pub fn load_flat_list(
    label: &str,
    v1_path: &Path,
    shipped: Shipped<'_>,
    local: &Verified,
    validate: EntryValidator<'_>,
) -> Result<OverlayLoad> {
    let (defaults, source) = load_defaults(label, v1_path, shipped, |name, body| {
        parse_default_text(name, body, validate)
    });
    let (adds, disables) = match (local.text(), local.source()) {
        (Some(text), Some(path)) => {
            parse_overlay_lines(&path.display().to_string(), text, validate, true)?
        }
        _ => Default::default(),
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
        defaults: source,
    })
}

/// Parse a `.v1` default list. Missing file → `Err`. Rejects `+`/`-`
/// prefixes (those are `.local`-only). Each entry is run through
/// `validate`.
pub fn parse_default_list(path: &Path, validate: EntryValidator<'_>) -> Result<BTreeSet<String>> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("reading default list {}", path.display()))?;
    Ok(parse_default_text(
        &path.display().to_string(),
        &body,
        validate,
    ))
}

/// Text form of [`parse_default_list`]; `label` names the source in the
/// line errors.
pub fn parse_default_text(
    label: &str,
    body: &str,
    validate: EntryValidator<'_>,
) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for (lineno, raw) in body.lines().enumerate() {
        let trimmed = strip_comment(raw).trim();
        if trimmed.is_empty() {
            continue;
        }
        // External audit FIMR-001: one bad line used to discard the whole
        // default list (FIM then watched nothing). It is skipped and
        // reported; every valid line still counts.
        if trimmed.starts_with('+') || trimmed.starts_with('-') {
            error!(
                "{}:{}: default list must not use +/- prefixes (those are local-overlay only) \
                 — line skipped",
                label,
                lineno + 1
            );
            continue;
        }
        if let Err(e) = validate(trimmed) {
            error!("{}:{}: {} — line skipped", label, lineno + 1, e);
            continue;
        }
        set.insert(trimmed.to_string());
    }
    set
}

/// Parse an overlay's text strictly (Tappa 10.8: the same rules validate
/// an overlay before it is signed or stored; the boot is lenient, see
/// [`load_flat_list`]). `label` prefixes the line number in errors.
pub fn parse_overlay_text(
    label: &str,
    body: &str,
    validate: EntryValidator<'_>,
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    parse_overlay_lines(label, body, validate, false)
}

/// `lenient`: a bad line is skipped and reported instead of failing the
/// text — the boot reading an overlay on disk (external audit FIMR-001: a
/// bad line used to drop the whole overlay). Content submitted for
/// signing is checked strictly, so the operator sees the error.
fn parse_overlay_lines(
    label: &str,
    body: &str,
    validate: EntryValidator<'_>,
    lenient: bool,
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let mut adds = BTreeSet::new();
    let mut disables = BTreeSet::new();
    for (lineno, raw) in body.lines().enumerate() {
        let trimmed = strip_comment(raw).trim();
        if trimmed.is_empty() {
            continue;
        }
        let (directive, rest) = split_directive(trimmed);
        if let Err(e) = validate(rest) {
            if !lenient {
                return Err(anyhow!("{}:{}: {}", label, lineno + 1, e));
            }
            error!("{}:{}: {} — line skipped", label, lineno + 1, e);
            continue;
        }
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
    /// the built-in copy): the merge tests below are about the overlay.
    fn load_own(v1: &Path, local: &Verified) -> OverlayLoad {
        let own = std::fs::read_to_string(v1).unwrap();
        load_flat_list(
            "test-allowlist",
            v1,
            Shipped::new(&own, &[]),
            local,
            &accept_any,
        )
        .expect("load")
    }

    const SHIPPED: &str = "sshd\nnginx\n";
    const EARLIER: &str = "sshd\nnginx\nevil-but-shipped-once\n";

    fn shipped_set() -> BTreeSet<String> {
        ["sshd", "nginx"].iter().map(|s| s.to_string()).collect()
    }

    fn load_test_list(v1: &Path, allow_modified: bool) -> (BTreeSet<String>, DefaultsSource) {
        let earlier = hex::encode(content_sha256(EARLIER.as_bytes()));
        let earlier = [earlier.as_str()];
        load_defaults_with(
            "test-allowlist",
            v1,
            Shipped::new(SHIPPED, &earlier),
            allow_modified,
            true,
            |name, body| parse_default_text(name, body, &accept_any),
        )
    }

    /// External audit LLMR-015: the `.v1` that is the built-in copy is the
    /// one used, and says so.
    #[test]
    fn current_default_is_used() {
        let dir = TempDir::new().unwrap();
        let v1 = dir.path().join("comm.v1");
        std::fs::write(&v1, SHIPPED).unwrap();
        let (set, source) = load_test_list(&v1, false);
        assert_eq!(set, shipped_set());
        assert_eq!(source, DefaultsSource::Disk);
    }

    /// External audit LLMR-015: a `.v1` edited by hand — an exemption added
    /// to an allowlist — is not applied: the built-in copy is, and the load
    /// reports the edit (both SHA-256) for the signed record. It used to be
    /// applied silently.
    #[test]
    fn modified_default_is_reported_and_not_applied() {
        let dir = TempDir::new().unwrap();
        let v1 = dir.path().join("comm.v1");
        std::fs::write(&v1, "sshd\nnginx\nimplant\n").unwrap();
        let (set, source) = load_test_list(&v1, false);
        assert_eq!(set, shipped_set(), "the edit must not take effect");
        let DefaultsSource::Modified {
            sha256,
            builtin_sha256,
            loaded_anyway,
        } = source
        else {
            panic!("an edited default list is reported, got {source:?}");
        };
        assert_eq!(
            sha256,
            hex::encode(content_sha256(b"sshd\nnginx\nimplant\n"))
        );
        assert_eq!(
            builtin_sha256,
            hex::encode(content_sha256(SHIPPED.as_bytes()))
        );
        assert!(!loaded_anyway);
        // A list emptied, or not even text: the same.
        std::fs::write(&v1, "").unwrap();
        let (set, source) = load_test_list(&v1, false);
        assert_eq!(set, shipped_set());
        assert!(matches!(source, DefaultsSource::Modified { .. }));
        std::fs::write(&v1, b"sshd\n\xff\xfe\n").unwrap();
        let (set, source) = load_test_list(&v1, false);
        assert_eq!(set, shipped_set());
        assert!(matches!(source, DefaultsSource::Modified { .. }));
        // The unsigned-configuration escape hatch applies it anyway, still
        // reported.
        std::fs::write(&v1, "sshd\nimplant\n").unwrap();
        let (set, source) = load_test_list(&v1, true);
        assert_eq!(
            set.into_iter().collect::<Vec<_>>(),
            vec!["implant".to_string(), "sshd".to_string()]
        );
        assert!(matches!(
            source,
            DefaultsSource::Modified {
                loaded_anyway: true,
                ..
            }
        ));
    }

    /// External audit LLMR-015: the list an earlier release shipped (an
    /// upgrade that did not replace it) gives way to the built-in copy —
    /// NET-011's CGNAT and VPN ranges left the blocklist in a release, and
    /// an upgraded host kept them.
    #[test]
    fn earlier_shipped_default_is_superseded() {
        let dir = TempDir::new().unwrap();
        let v1 = dir.path().join("comm.v1");
        std::fs::write(&v1, EARLIER).unwrap();
        let (set, source) = load_test_list(&v1, false);
        assert_eq!(set, shipped_set());
        assert_eq!(
            source,
            DefaultsSource::Superseded {
                sha256: hex::encode(content_sha256(EARLIER.as_bytes()))
            }
        );
    }

    /// External audit LLMR-015: a `.v1` is read like an overlay — not
    /// through a link (its target is anything root points it at), not from
    /// a FIFO (the boot would block on it) — and gives way to the built-in
    /// copy, reported as unavailable.
    #[test]
    fn default_through_a_link_or_fifo_is_refused() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, "implant\n").unwrap();
        let link = dir.path().join("link.v1");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let (set, source) = load_test_list(&link, true);
        assert_eq!(set, shipped_set());
        assert!(
            matches!(&source, DefaultsSource::BuiltIn(why) if why.contains("symbolic link")),
            "{source:?}"
        );
        // Even when the link points at the shipped content.
        std::fs::write(&target, SHIPPED).unwrap();
        let (_, source) = load_test_list(&link, false);
        assert!(matches!(source, DefaultsSource::BuiltIn(_)));

        let fifo = dir.path().join("fifo.v1");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo has no other preconditions.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let (set, source) = load_test_list(&fifo, false);
        assert_eq!(set, shipped_set());
        assert!(
            matches!(&source, DefaultsSource::BuiltIn(why) if why.contains("not a regular file")),
            "{source:?}"
        );
    }

    /// Every shipped default list: its file name in `/etc/northnarrow` and
    /// its shipped copies.
    fn shipped_lists() -> [(&'static str, Shipped<'static>); 6] {
        [
            ("fim-paths.v1", crate::fim::paths_config::FIM_PATHS_SHIPPED),
            (
                "netflow-blocklist.v1",
                crate::net::blocklist::NETFLOW_BLOCKLIST_SHIPPED,
            ),
            (
                "netflow-ja3-blocklist.v1",
                crate::net::blocklist::JA3_BLOCKLIST_SHIPPED,
            ),
            (
                "process-comm-allowlist.v1",
                crate::config::comm_allowlist::PROCESS_COMM_ALLOWLIST_SHIPPED,
            ),
            (
                "netflow-comm-allowlist.v1",
                crate::config::comm_allowlist::NETFLOW_COMM_ALLOWLIST_SHIPPED,
            ),
            // Lab PR 225.
            ("security-tools.v1", crate::impair::SECURITY_TOOLS_SHIPPED),
        ]
    }

    /// External audit LLMR-015: `install.sh` replaces exactly the copies the
    /// agent supersedes — its `SHIPPED_V1_EARLIER` table is the agent's —
    /// and installs every list through the same check.
    #[test]
    fn install_sh_knows_the_same_shipped_lists() {
        use std::collections::BTreeMap;
        let install =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../deploy/install.sh"))
                .unwrap();
        let start = install
            .find("declare -A SHIPPED_V1_EARLIER=(")
            .expect("deploy/install.sh declares SHIPPED_V1_EARLIER");
        let block = &install[start..];
        let block = &block[..block.find("\n)").unwrap()];
        let mut table = BTreeMap::new();
        for line in block.lines().skip(1) {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, hashes) = line
                .strip_prefix('[')
                .and_then(|l| l.split_once("]="))
                .unwrap_or_else(|| panic!("unexpected line in SHIPPED_V1_EARLIER: {line}"));
            let hashes: BTreeSet<String> = hashes
                .trim_matches('"')
                .split_whitespace()
                .map(String::from)
                .collect();
            table.insert(name.to_string(), hashes);
        }
        let ours: BTreeMap<String, BTreeSet<String>> = shipped_lists()
            .iter()
            .map(|(name, shipped)| {
                (
                    name.to_string(),
                    shipped
                        .earlier_sha256
                        .iter()
                        .map(|h| h.to_string())
                        .collect(),
                )
            })
            .collect();
        assert_eq!(table, ours);
        for (name, _) in shipped_lists() {
            assert!(
                install.contains(&format!("install_shipped_v1 {name} ")),
                "install.sh installs {name} through install_shipped_v1"
            );
        }
    }

    /// External audit LLMR-015: the built-in copy of each list, pinned. A
    /// change to `configs/<list>.v1` turns the copy every installed host has
    /// into an "edited" one unless its SHA-256 moves to the earlier ones,
    /// here and in `install.sh`.
    #[test]
    fn the_shipped_lists_are_pinned() {
        let pins = [
            (
                "fim-paths.v1",
                "44a5f17e037148eb31a8798d7c0918e31d4657ba2ca7003b696a775741326508",
            ),
            (
                "netflow-blocklist.v1",
                "4588710cd342c6eeb5054acb108d47aa6dbf020feb768c8775fdc2d30e4c84f9",
            ),
            (
                "netflow-ja3-blocklist.v1",
                "3549750f6c1530fc139f9853d173bccb72612b58086392517fa9fe1f3a815870",
            ),
            (
                "process-comm-allowlist.v1",
                "a096c0dc64852fba9861009935028b28888307ae04dee99f4aa51f6b72ffdea0",
            ),
            (
                "netflow-comm-allowlist.v1",
                "46a1965afe80c7b578bb3584126f35a46d678bd59a6e2ca59081f65381d93266",
            ),
            (
                "security-tools.v1",
                "38cef57a92f6b394be9307c0f16e8799d553d0cff7bb6d7fd3db0b3906736335",
            ),
        ];
        for ((name, shipped), (pin_name, pin)) in shipped_lists().into_iter().zip(pins) {
            assert_eq!(name, pin_name);
            let sha = shipped.builtin_sha256();
            assert_eq!(
                sha, pin,
                "configs/{name} changed: add {pin} to its EARLIER_*_SHA256 table and to \
                 SHIPPED_V1_EARLIER in deploy/install.sh, then pin {sha} here"
            );
            assert!(!shipped.earlier_sha256.contains(&pin));
            let distinct: BTreeSet<&&str> = shipped.earlier_sha256.iter().collect();
            assert_eq!(distinct.len(), shipped.earlier_sha256.len(), "{name}");
            for h in shipped.earlier_sha256 {
                assert!(
                    h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
                    "{name}: {h}"
                );
            }
            let file = std::fs::read_to_string(format!(
                "{}/../configs/{name}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap();
            assert_eq!(
                file, shipped.builtin,
                "{name}: the built-in copy is configs/"
            );
        }
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
        let out = load_own(&v1, &verified(&local));
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
        let out = load_own(&v1, &verified(&local));

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
        let out = load_own(&v1, &verified(&local));

        // Defaults unchanged (the disable hit nothing).
        let expected: BTreeSet<String> = ["sshd", "nginx"].iter().map(|s| s.to_string()).collect();
        assert_eq!(out.effective, expected);
        assert!(out.disabled.is_empty());
        assert!(out.unknown_disable.contains("not-a-default-comm"));
    }

    /// External audit LLMR-016: a `.v1` that cannot be read gives way to
    /// the copy built into the agent — the load says so — and the overlay
    /// still applies on top; a `.v1` that is the built-in copy is the one
    /// used, one that is not gives way to it (LLMR-015).
    #[test]
    fn a_missing_default_list_uses_the_built_in_copy() {
        let dir = TempDir::new().unwrap();
        let out = load_flat_list(
            "test-allowlist",
            &dir.path().join("missing.v1"),
            Shipped::new("sshd\nnginx\n", &[]),
            &Verified::Content {
                path: dir.path().join("comm.local"),
                text: "-nginx\n+backupd\n".to_string(),
            },
            &accept_any,
        )
        .expect("a missing default list is tolerated");
        let expected: BTreeSet<String> =
            ["sshd", "backupd"].iter().map(|s| s.to_string()).collect();
        assert_eq!(out.effective, expected);
        assert!(matches!(out.defaults, DefaultsSource::BuiltIn(_)));

        let v1 = dir.path().join("comm.v1");
        std::fs::write(&v1, "curl\n").unwrap();
        let out = load_flat_list(
            "test-allowlist",
            &v1,
            Shipped::new("curl\n", &[]),
            &Verified::Missing,
            &accept_any,
        )
        .unwrap();
        assert_eq!(out.defaults, DefaultsSource::Disk);
        assert_eq!(out.effective.into_iter().collect::<Vec<_>>(), vec!["curl"]);
        let out = load_flat_list(
            "test-allowlist",
            &v1,
            Shipped::new("sshd\n", &[]),
            &Verified::Missing,
            &accept_any,
        )
        .unwrap();
        assert!(matches!(out.defaults, DefaultsSource::Modified { .. }));
        assert_eq!(out.effective.into_iter().collect::<Vec<_>>(), vec!["sshd"]);
    }

    /// D1: a `.v1` carrying a `+`/`-` directive (a `.local` template
    /// copied over the default) is rejected up-front so the install
    /// error surfaces at boot.
    #[test]
    fn parse_default_list_rejects_directive_prefixes() {
        let dir = TempDir::new().unwrap();
        let v1 = dir.path().join("comm.v1");
        std::fs::write(&v1, "sshd\n+oops-overlay-syntax\n").unwrap();
        // External audit FIMR-001: the directive line is skipped, the rest
        // of the list kept.
        let set = parse_default_list(&v1, &accept_any).expect("a bad line is not a bad list");
        assert_eq!(
            set.into_iter().collect::<Vec<_>>(),
            vec!["sshd".to_string()]
        );
    }
}
