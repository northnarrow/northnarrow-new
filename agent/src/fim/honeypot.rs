//! Tappa 9.5.1 — anti-tamper bait content + boot integrity check.
//!
//! The detection rule (NN-L-FIM-024, `fim::rules`) only *watches* the
//! [`crate::fim::rules::HONEYPOT_PATHS`]; this module owns their inert
//! content and the boot-time integrity sweep.
//!
//! **Single source of truth.** Each bait's bytes live once, in
//! `configs/honeypot-baits/<basename>`, and are `include_str!`'d here so
//! the agent's recreate is byte-identical to what `deploy/install.sh`
//! copies in — no Rust-vs-shell content drift is possible. `last_modified`
//! is a fixed plausible date (determinism > a live timestamp; a static
//! date is equally convincing as bait).
//!
//! **No deception leak.** None of the embedded content nor the paths
//! carry "honeypot/decoy/canary/bait/trap" — an attacker reading these
//! on a compromised host must see only plausible NN control config.

use std::io;
use std::path::Path;

use crate::fim::rules::HONEYPOT_PATHS;

macro_rules! bait {
    ($name:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../configs/honeypot-baits/",
            $name
        ))
    };
}

/// The inert content for a honeypot path, embedded from
/// `configs/honeypot-baits/`. `None` for any path not in
/// [`HONEYPOT_PATHS`].
pub fn bait_content(path: &str) -> Option<&'static str> {
    Some(match path {
        "/etc/northnarrow/agent.dev.lock" => bait!("agent.dev.lock"),
        "/etc/northnarrow/kill_switch.conf" => bait!("kill_switch.conf"),
        "/etc/northnarrow/maintenance.mode" => bait!("maintenance.mode"),
        "/etc/northnarrow/debug_disable.flag" => bait!("debug_disable.flag"),
        "/etc/northnarrow/agent.legacy.conf" => bait!("agent.legacy.conf"),
        "/var/lib/northnarrow/shutdown.signal" => bait!("shutdown.signal"),
        "/var/lib/northnarrow/disable.token" => bait!("disable.token"),
        "/var/lib/northnarrow/override.config" => bait!("override.config"),
        "/run/northnarrow/pause.flag" => bait!("pause.flag"),
        "/run/northnarrow/unload.signal" => bait!("unload.signal"),
        _ => return None,
    })
}

/// Outcome of the boot integrity sweep ([`check_and_restore`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoneypotIntegrityReport {
    pub total: usize,
    pub present: usize,
    /// Paths that were missing and have been recreated from template.
    pub recreated: Vec<String>,
    /// Paths that were missing but could NOT be recreated (e.g. an EPERM
    /// from the anti-tamper deny layer before the agent is exempt). A
    /// failure here does not abort the sweep — the remaining baits are
    /// still restored.
    pub failed: Vec<String>,
}

impl HoneypotIntegrityReport {
    /// `true` when every bait was already on disk (nothing recreated,
    /// nothing failed).
    pub fn all_present(&self) -> bool {
        self.recreated.is_empty() && self.failed.is_empty()
    }
}

/// Boot-time integrity sweep (RFC Q5). For each [`HONEYPOT_PATHS`] entry:
/// present → counted; missing → recreated from its embedded template
/// (parent dir created first — covers the tmpfs `/run/northnarrow` after
/// a reboot); missing-but-unrestorable → recorded in `failed` WITHOUT
/// aborting the rest of the sweep. The caller logs Info (all present) or
/// Medium (anything recreated/failed). The recreate is an agent write —
/// the agent is in `PROTECTED_PIDS`, so it cannot self-trigger
/// NN-L-FIM-024 (the rule also carries an `own_pid` backstop).
pub fn check_and_restore() -> HoneypotIntegrityReport {
    restore_paths(HONEYPOT_PATHS.iter().map(|p| {
        let c = bait_content(p).expect("every HONEYPOT_PATH has a template");
        (*p, c)
    }))
}

/// Inner sweep over explicit `(path, content)` pairs — the testable core
/// (tests pass tempdir-rooted paths so no real `/etc` is touched). Never
/// aborts: a per-path write failure is collected into `failed`.
fn restore_paths<'a>(items: impl Iterator<Item = (&'a str, &'a str)>) -> HoneypotIntegrityReport {
    let mut total = 0;
    let mut present = 0;
    let mut recreated = Vec::new();
    let mut failed = Vec::new();
    for (path, content) in items {
        total += 1;
        if Path::new(path).exists() {
            present += 1;
            continue;
        }
        let restored = (|| -> io::Result<()> {
            if let Some(parent) = Path::new(path).parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, content)
        })();
        match restored {
            Ok(()) => recreated.push(path.to_string()),
            Err(_) => failed.push(path.to_string()),
        }
    }
    HoneypotIntegrityReport {
        total,
        present,
        recreated,
        failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_honeypot_path_has_embedded_content() {
        for p in HONEYPOT_PATHS {
            let c = bait_content(p).unwrap_or_else(|| panic!("no template for {p}"));
            assert!(c.len() > 50, "bait {p} content too short");
            assert!(
                c.starts_with("# NorthNarrow Agent -"),
                "bait {p} missing realistic config header"
            );
        }
        assert!(
            bait_content("/etc/northnarrow/agent.conf").is_none(),
            "non-bait path must have no template"
        );
    }

    #[test]
    fn bait_content_has_no_deception_leak() {
        let banned = ["honeypot", "decoy", "canary", "bait", "trap"];
        for p in HONEYPOT_PATHS {
            let c = bait_content(p).unwrap().to_lowercase();
            for b in banned {
                assert!(!c.contains(b), "leaky term {b:?} in bait content for {p}");
            }
        }
    }

    #[test]
    fn restore_recreates_missing_and_counts_present() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.conf");
        let b = dir.path().join("sub/b.flag"); // parent missing → created
        std::fs::write(&a, "ALREADY").unwrap();
        let (ap, bp) = (a.to_str().unwrap(), b.to_str().unwrap());

        let rep = restore_paths([(ap, "CONTENT_A"), (bp, "CONTENT_B")].into_iter());

        assert_eq!(rep.total, 2);
        assert_eq!(rep.present, 1, "a.conf already present");
        assert_eq!(rep.recreated, vec![bp.to_string()]);
        assert!(!rep.all_present());
        // Present file untouched; missing file recreated exactly.
        assert_eq!(std::fs::read_to_string(&a).unwrap(), "ALREADY");
        assert_eq!(std::fs::read_to_string(&b).unwrap(), "CONTENT_B");
    }

    #[test]
    fn restore_all_present_recreates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        std::fs::write(&a, "x").unwrap();
        let ap = a.to_str().unwrap();
        let rep = restore_paths([(ap, "x")].into_iter());
        assert!(rep.all_present());
        assert_eq!(rep.present, 1);
        assert!(rep.recreated.is_empty());
    }

    #[test]
    fn deployed_fim_paths_config_has_no_deception_leak() {
        // fim-paths.v1 is installed to /etc/northnarrow (0644,
        // attacker-readable) — its honeypot section must not reveal the
        // deception either.
        let cfg = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../configs/fim-paths.v1"
        ))
        .to_lowercase();
        for b in ["honeypot", "decoy", "bait", "trap"] {
            assert!(
                !cfg.contains(b),
                "leaky term {b:?} in deployed fim-paths.v1"
            );
        }
    }

    #[test]
    fn recreated_file_matches_template_exactly() {
        // The agent recreate writes bait_content() verbatim — the same
        // bytes deploy/install.sh copies from configs/honeypot-baits/.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("kill_switch.conf");
        let pp = p.to_str().unwrap();
        let want = bait_content("/etc/northnarrow/kill_switch.conf").unwrap();
        let rep = restore_paths([(pp, want)].into_iter());
        assert_eq!(rep.recreated, vec![pp.to_string()]);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), want);
    }
}
