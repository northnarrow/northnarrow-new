//! `cow-guard.local`: the copy-on-first-write guard's configuration.
//!
//! A signed operator overlay ([`common::wire::admin_signed_payload::OverlayKind::CowGuard`]),
//! loaded through the overlay gate like the other `*.local` files: root
//! cannot widen the trusted writers, shrink a scope or switch the guard
//! off without an admin key carrying `config-manage`. Absent, refused or
//! `enabled = false`: the guard does not run (the default of this lot).
//!
//! One `key = value` per line, `#` comments:
//!
//! ```text
//! enabled = true
//! scope = /srv                      # mark=dirs, budget=1GiB by default
//! scope = /home mark=dirs budget=4GiB
//! scope = /mnt/data mark=filesystem budget=8GiB journal=/mnt/data/.nn-cow
//! copy_cap = 16MiB                  # largest file copied byte for byte
//! event_budget_ms = 50              # a copy's budget (the open is answered by then + 25 ms)
//! retention_hours = 24              # from a copy's last use
//! eviction_floor_minutes = 15       # copies used more recently are never evicted
//! min_free_percent = 5
//! auto_restore = false              # restore after NEUTRALIZE or NN-L-FIM-010's kill (off by default)
//! trusted_writer = vim              # added to the built-in trusted writers
//! ```
//!
//! The parser is strict: an unknown key, a relative scope, a scope under
//! the agent's own directories or a value out of range is an error, so a
//! signature never covers content the loader would read differently.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};

/// Default path of the overlay.
pub const COW_GUARD_LOCAL: &str = "/etc/northnarrow/cow-guard.local";

/// Default byte budget of a scope's journal.
pub const DEFAULT_SCOPE_BUDGET: u64 = 1 << 30;
/// Default largest file copied byte for byte (reflinks are bounded by the
/// scope's budget only).
pub const DEFAULT_COPY_CAP: u64 = 16 << 20;
/// Default budget of a copy: past it the backstop answers the open (at most
/// `guard::COPY_ANSWER_BOUND`, 25 ms, later) and the copy is discarded.
pub const DEFAULT_EVENT_BUDGET_MS: u64 = 50;
/// Default retention of a copy, from its last use (taken or shared).
pub const DEFAULT_RETENTION_HOURS: u64 = 24;
/// Default time since its last use under which a copy is never evicted for
/// space.
pub const DEFAULT_EVICTION_FLOOR_MINUTES: u64 = 15;
/// Default free space below which no copy is taken.
pub const DEFAULT_MIN_FREE_PERCENT: u8 = 5;
/// Default number of directories marked per scope (`mark=dirs`).
pub const DEFAULT_MAX_DIR_MARKS: usize = 8192;
/// Default number of copier threads.
pub const DEFAULT_COPIERS: usize = 2;
/// Name of the journal directory at the root of a scope (default).
pub const JOURNAL_DIR_NAME: &str = ".northnarrow-cow";

/// How a scope is marked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkKind {
    /// An inode mark on every directory of the tree (`FAN_EVENT_ON_CHILD`),
    /// bounded by `max_dir_marks` and refreshed by a rescan. Only opens in
    /// the tree reach the agent.
    Dirs,
    /// `FAN_MARK_MOUNT` on the scope, which must be a mount point: every
    /// open through that mount reaches the agent.
    Mount,
    /// `FAN_MARK_FILESYSTEM` on the scope, which must be a mount point:
    /// every open on that filesystem, through any mount, reaches the agent.
    Filesystem,
}

impl MarkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            MarkKind::Dirs => "dirs",
            MarkKind::Mount => "mount",
            MarkKind::Filesystem => "filesystem",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "dirs" => MarkKind::Dirs,
            "mount" => MarkKind::Mount,
            "filesystem" => MarkKind::Filesystem,
            other => bail!("mark must be dirs, mount or filesystem (got `{other}`)"),
        })
    }
}

/// One protected scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeConfig {
    /// Absolute, normalised (no `.`/`..`, no trailing `/`).
    pub path: PathBuf,
    pub mark: MarkKind,
    /// Bytes of original content the scope's journal may hold (each copy
    /// counted at its logical size, a reflink too: an attacker who rewrites
    /// the whole file unshares every block).
    pub budget: u64,
    /// Root-only journal directory; on the scope's filesystem for reflink.
    pub journal: PathBuf,
}

/// The guard's configuration, parsed from `cow-guard.local`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CowConfig {
    pub enabled: bool,
    pub scopes: Vec<ScopeConfig>,
    pub copy_cap: u64,
    pub event_budget_ms: u64,
    pub retention_hours: u64,
    pub eviction_floor_minutes: u64,
    pub min_free_percent: u8,
    pub auto_restore: bool,
    /// Added to [`super::trust::BUILTIN_TRUSTED_WRITERS`].
    pub trusted_writers: Vec<String>,
    pub max_dir_marks: usize,
    pub copiers: usize,
}

impl Default for CowConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scopes: Vec::new(),
            copy_cap: DEFAULT_COPY_CAP,
            event_budget_ms: DEFAULT_EVENT_BUDGET_MS,
            retention_hours: DEFAULT_RETENTION_HOURS,
            eviction_floor_minutes: DEFAULT_EVICTION_FLOOR_MINUTES,
            min_free_percent: DEFAULT_MIN_FREE_PERCENT,
            auto_restore: false,
            trusted_writers: Vec::new(),
            max_dir_marks: DEFAULT_MAX_DIR_MARKS,
            copiers: DEFAULT_COPIERS,
        }
    }
}

/// Paths a scope may never cover or sit under: the agent's own state,
/// configuration and runtime directories, and pseudo-filesystems.
const REFUSED_SCOPE_PREFIXES: &[&str] = &[
    "/etc/northnarrow",
    "/var/lib/northnarrow",
    "/run",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
];

/// Parse a size: bytes, or a number with `KiB`, `MiB`, `GiB` (also `K`,
/// `M`, `G`).
pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    if num.is_empty() {
        bail!("size `{s}` has no number");
    }
    let n: u64 = num.parse().map_err(|e| anyhow!("size `{s}`: {e}"))?;
    let mult: u64 = match unit.trim() {
        "" | "B" => 1,
        "K" | "KiB" => 1 << 10,
        "M" | "MiB" => 1 << 20,
        "G" | "GiB" => 1 << 30,
        other => bail!("size `{s}`: unit must be KiB, MiB or GiB (got `{other}`)"),
    };
    n.checked_mul(mult)
        .ok_or_else(|| anyhow!("size `{s}` overflows"))
}

/// An absolute path without `.`, `..`, empty components or a trailing `/`
/// (except `/` itself, which is refused as a scope anyway).
fn normalised_absolute(s: &str, what: &str) -> Result<PathBuf> {
    if !s.starts_with('/') {
        bail!("{what} must be an absolute path (got `{s}`)");
    }
    let trimmed = s.trim_end_matches('/');
    if trimmed.is_empty() {
        bail!("{what} cannot be `/`");
    }
    for comp in trimmed[1..].split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            bail!("{what} `{s}` must be normalised (no `.`, `..` or `//`)");
        }
    }
    if trimmed.contains(char::is_whitespace) || trimmed.contains('\0') {
        bail!("{what} `{s}` holds whitespace");
    }
    Ok(PathBuf::from(trimmed))
}

fn under(path: &Path, prefix: &str) -> bool {
    path.starts_with(prefix)
}

fn parse_scope(value: &str) -> Result<ScopeConfig> {
    let mut parts = value.split_whitespace();
    let path = parts.next().ok_or_else(|| anyhow!("scope needs a path"))?;
    let path = normalised_absolute(path, "scope")?;
    for p in REFUSED_SCOPE_PREFIXES {
        if under(&path, p) || Path::new(p).starts_with(&path) {
            bail!(
                "scope `{}` overlaps `{p}` (the agent's own or a pseudo-filesystem)",
                path.display()
            );
        }
    }
    let mut mark = MarkKind::Dirs;
    let mut budget = DEFAULT_SCOPE_BUDGET;
    let mut journal = path.join(JOURNAL_DIR_NAME);
    for opt in parts {
        let (k, v) = opt
            .split_once('=')
            .ok_or_else(|| anyhow!("scope option `{opt}` is not key=value"))?;
        match k {
            "mark" => mark = MarkKind::parse(v)?,
            "budget" => {
                budget = parse_size(v)?;
                if budget < (1 << 20) {
                    bail!("scope budget `{v}` is under 1MiB");
                }
            }
            "journal" => {
                journal = normalised_absolute(v, "journal")?;
                for p in REFUSED_SCOPE_PREFIXES {
                    if under(&journal, p) {
                        bail!("journal `{}` is under `{p}`", journal.display());
                    }
                }
            }
            other => bail!("unknown scope option `{other}` (mark, budget, journal)"),
        }
    }
    Ok(ScopeConfig {
        path,
        mark,
        budget,
        journal,
    })
}

fn parse_bool(v: &str) -> Result<bool> {
    match v {
        "true" | "yes" | "1" => Ok(true),
        "false" | "no" | "0" => Ok(false),
        other => bail!("expected true or false (got `{other}`)"),
    }
}

fn parse_ranged(v: &str, lo: u64, hi: u64, what: &str) -> Result<u64> {
    let n: u64 = v
        .parse()
        .map_err(|e| anyhow!("{what} `{v}` is not a number: {e}"))?;
    if !(lo..=hi).contains(&n) {
        bail!("{what} must be within {lo}..={hi} (got {n})");
    }
    Ok(n)
}

impl CowConfig {
    /// Parse the overlay text strictly (see the module documentation).
    pub fn parse(text: &str) -> Result<Self> {
        let mut c = CowConfig::default();
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let at = |e: anyhow::Error| anyhow!("cow-guard.local:{}: {e}", lineno + 1);
            let (key, value) = line
                .split_once('=')
                .map(|(k, v)| (k.trim(), v.trim()))
                .ok_or_else(|| at(anyhow!("expected `key = value` (got `{line}`)")))?;
            match key {
                "enabled" => c.enabled = parse_bool(value).map_err(at)?,
                "auto_restore" => c.auto_restore = parse_bool(value).map_err(at)?,
                "scope" => c.scopes.push(parse_scope(value).map_err(at)?),
                "copy_cap" => {
                    c.copy_cap = parse_size(value).map_err(at)?;
                    if c.copy_cap > (1 << 30) {
                        return Err(at(anyhow!("copy_cap is over 1GiB")));
                    }
                }
                "event_budget_ms" => {
                    c.event_budget_ms =
                        parse_ranged(value, 5, 500, "event_budget_ms").map_err(at)?
                }
                "retention_hours" => {
                    c.retention_hours =
                        parse_ranged(value, 1, 168, "retention_hours").map_err(at)?
                }
                "eviction_floor_minutes" => {
                    c.eviction_floor_minutes =
                        parse_ranged(value, 0, 24 * 60, "eviction_floor_minutes").map_err(at)?
                }
                "min_free_percent" => {
                    c.min_free_percent =
                        parse_ranged(value, 0, 50, "min_free_percent").map_err(at)? as u8
                }
                "max_dir_marks" => {
                    c.max_dir_marks =
                        parse_ranged(value, 1, 1 << 20, "max_dir_marks").map_err(at)? as usize
                }
                "copiers" => c.copiers = parse_ranged(value, 1, 8, "copiers").map_err(at)? as usize,
                "trusted_writer" => {
                    super::trust::validate_writer(value).map_err(at)?;
                    c.trusted_writers.push(value.to_string());
                }
                other => {
                    return Err(at(anyhow!(
                        "unknown key `{other}` (enabled, scope, copy_cap, event_budget_ms, \
                         retention_hours, eviction_floor_minutes, min_free_percent, \
                         auto_restore, trusted_writer, max_dir_marks, copiers)"
                    )))
                }
            }
        }
        for (i, a) in c.scopes.iter().enumerate() {
            for b in &c.scopes[i + 1..] {
                if a.path.starts_with(&b.path) || b.path.starts_with(&a.path) {
                    bail!(
                        "cow-guard.local: scopes `{}` and `{}` overlap",
                        a.path.display(),
                        b.path.display()
                    );
                }
            }
        }
        if c.enabled && c.scopes.is_empty() {
            bail!("cow-guard.local: enabled with no scope");
        }
        Ok(c)
    }

    /// Validation for `nn-admin config overlay set|sign cow-guard`.
    pub fn validate(text: &str) -> Result<()> {
        Self::parse(text).map(|_| ())
    }

    /// The scope `path` lies in, by index.
    pub fn scope_of(&self, path: &Path) -> Option<usize> {
        self.scopes.iter().position(|s| path.starts_with(&s.path))
    }

    /// `path` lies in a journal directory.
    pub fn in_journal(&self, path: &Path) -> bool {
        self.scopes.iter().any(|s| path.starts_with(&s.journal))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_off() {
        let c = CowConfig::parse("").unwrap();
        assert!(!c.enabled);
        assert!(!c.auto_restore);
        assert_eq!(c.copy_cap, 16 << 20);
        assert_eq!(c.event_budget_ms, 50);
        assert_eq!(c.retention_hours, 24);
    }

    #[test]
    fn a_full_overlay_parses() {
        let c = CowConfig::parse(
            "# lab\nenabled = true\nscope = /srv/nn-cow-test\n\
             scope = /mnt/x mark=filesystem budget=2GiB journal=/mnt/x/.j\n\
             copy_cap = 8MiB\nevent_budget_ms = 40\nauto_restore = yes\n\
             trusted_writer = vim\ntrusted_writer = /opt/editor/\n",
        )
        .unwrap();
        assert!(c.enabled && c.auto_restore);
        assert_eq!(c.scopes.len(), 2);
        assert_eq!(c.scopes[0].mark, MarkKind::Dirs);
        assert_eq!(c.scopes[0].budget, DEFAULT_SCOPE_BUDGET);
        assert_eq!(
            c.scopes[0].journal,
            PathBuf::from("/srv/nn-cow-test/.northnarrow-cow")
        );
        assert_eq!(c.scopes[1].mark, MarkKind::Filesystem);
        assert_eq!(c.scopes[1].budget, 2 << 30);
        assert_eq!(c.scopes[1].journal, PathBuf::from("/mnt/x/.j"));
        assert_eq!(c.copy_cap, 8 << 20);
        assert_eq!(c.trusted_writers, vec!["vim", "/opt/editor/"]);
        assert_eq!(c.scope_of(Path::new("/srv/nn-cow-test/a/b")), Some(0));
        assert_eq!(c.scope_of(Path::new("/srv/other")), None);
        assert!(c.in_journal(Path::new("/mnt/x/.j/objects/1")));
    }

    #[test]
    fn bad_content_is_refused_with_its_line() {
        for (text, needle) in [
            ("enabled = maybe", "true or false"),
            ("scope = srv", "absolute"),
            ("scope = /", "cannot be `/`"),
            ("scope = /srv/../etc", "normalised"),
            ("scope = /var/lib/northnarrow/x", "agent's own"),
            ("scope = /var", "agent's own"),
            ("scope = /srv mark=everything", "dirs, mount or filesystem"),
            ("scope = /srv budget=10", "under 1MiB"),
            ("scope = /srv colour=red", "unknown scope option"),
            ("scope = /srv\nscope = /srv/www", "overlap"),
            ("event_budget_ms = 0", "5..=500"),
            ("event_budget_ms = 10000", "5..=500"),
            ("copy_cap = 2GiB", "over 1GiB"),
            ("copy_cap = 16TB", "unit"),
            ("trusted_writer = /tmp/x", "program name"),
            ("trusted_writer = bash", "interpreter"),
            ("colour = red", "unknown key"),
            ("enabled = true", "no scope"),
            ("just words", "key = value"),
        ] {
            let err = format!("{:#}", CowConfig::parse(text).unwrap_err());
            assert!(err.contains(needle), "{text:?}: {err}");
        }
        let err = format!(
            "{:#}",
            CowConfig::parse("enabled = false\n\nscope = srv").unwrap_err()
        );
        assert!(err.contains("cow-guard.local:3"), "{err}");
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert_eq!(parse_size("16MiB").unwrap(), 16 << 20);
        assert_eq!(parse_size("2G").unwrap(), 2 << 30);
        assert_eq!(parse_size("512KiB").unwrap(), 512 << 10);
        assert!(parse_size("MiB").is_err());
        assert!(parse_size("99999999999999GiB").is_err());
    }
}
