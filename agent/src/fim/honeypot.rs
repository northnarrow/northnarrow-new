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

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::fim::rules::HONEYPOT_PATHS;

/// A bait's mode, as `deploy/install.sh` writes it: readable, so that a
/// look at it is plausible; root's to change.
const BAIT_MODE: u32 = 0o644;
/// A missing bait directory (the tmpfs `/run/northnarrow` outside
/// systemd) is created as systemd's `RuntimeDirectoryMode` would.
const BAIT_DIR_MODE: u32 = 0o700;

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
    /// External audit FIMR-009: paths that held something other than a
    /// regular file — a symlink (it made the bait "present" while the
    /// watch landed on the link, and a write through it went unseen), a
    /// FIFO, a directory. Each was removed and re-created, so it is also
    /// in `recreated` (or `failed`).
    pub replaced: Vec<String>,
}

impl HoneypotIntegrityReport {
    /// `true` when every bait was already on disk (nothing recreated,
    /// nothing failed).
    pub fn all_present(&self) -> bool {
        self.recreated.is_empty() && self.failed.is_empty() && self.replaced.is_empty()
    }

    /// External audit FIMR-008: only the tmpfs baits under `/run` went
    /// missing, after a reboot — their expected state on every boot.
    pub fn only_volatile_after_reboot(&self, rebooted: bool) -> bool {
        rebooted
            && self.failed.is_empty()
            && self.replaced.is_empty()
            && self.recreated.iter().all(|p| p.starts_with("/run/"))
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
    let mut replaced = Vec::new();
    for (path, content) in items {
        total += 1;
        let p = Path::new(path);
        // External audit FIMR-009: judged without following a link. A link
        // to an existing file was "present", and the restore wrote through
        // a dangling one.
        match fs::symlink_metadata(p) {
            Ok(m) if m.file_type().is_file() => {
                present += 1;
                continue;
            }
            Ok(m) => {
                replaced.push(path.to_string());
                // Removes the link itself (or an empty directory), never
                // what it points to.
                let removed = if m.is_dir() {
                    fs::remove_dir(p)
                } else {
                    fs::remove_file(p)
                };
                if removed.is_err() {
                    failed.push(path.to_string());
                    continue;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                failed.push(path.to_string());
                continue;
            }
        }
        match create_bait(p, content) {
            Ok(()) => recreated.push(path.to_string()),
            Err(_) => failed.push(path.to_string()),
        }
    }
    HoneypotIntegrityReport {
        total,
        present,
        recreated,
        failed,
        replaced,
    }
}

/// Create `path` exclusively — never through a link, never over what
/// appeared since the check — with `content` and [`BAIT_MODE`]. A missing
/// parent is created at [`BAIT_DIR_MODE`]; an existing one keeps its mode.
fn create_bait(path: &Path, content: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && fs::symlink_metadata(parent).is_err() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(BAIT_DIR_MODE)
                .create(parent)?;
        }
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(BAIT_MODE)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    f.write_all(content.as_bytes())?;
    // The umask may have narrowed the mode at creation.
    f.set_permissions(fs::Permissions::from_mode(BAIT_MODE))
}

/// External audit FIMR-008: the file in the state directory holding the
/// kernel boot id the agent last ran under.
pub const BOOT_ID_FILE: &str = "last_boot_id";

/// The kernel's boot id, `None` when it cannot be read.
pub fn current_boot_id() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// External audit FIMR-008: whether the host rebooted since the agent last
/// ran — `now` against the boot id recorded in `state_dir`. No record
/// (first run, an unreadable one) counts as a reboot: the `/run` baits are
/// then missing as after one.
pub fn boot_changed(state_dir: &Path, now: &str) -> bool {
    fs::read_to_string(state_dir.join(BOOT_ID_FILE)).map_or(true, |last| last.trim() != now)
}

/// Record `now` in `state_dir`: a temporary created exclusively, then
/// renamed over — a link planted at either name is replaced, never written
/// through. The caller lifts the directory's immutability around it.
pub fn write_boot_id(state_dir: &Path, now: &str) -> io::Result<()> {
    let file = state_dir.join(BOOT_ID_FILE);
    let tmp = state_dir.join(format!("{BOOT_ID_FILE}.tmp"));
    let _ = fs::remove_file(&tmp);
    let written = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| f.write_all(format!("{now}\n").as_bytes()))
        .and_then(|()| fs::rename(&tmp, &file));
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
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

    /// External audit FIMR-009: a link where a bait belongs made it
    /// "present"; it is replaced, and what it pointed to is left alone.
    #[test]
    fn restore_replaces_a_symlinked_bait_and_leaves_the_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, "THEIRS").unwrap();
        let bait = dir.path().join("pause.flag");
        std::os::unix::fs::symlink(&target, &bait).unwrap();
        let bp = bait.to_str().unwrap();
        let rep = restore_paths([(bp, "BAIT")].into_iter());
        assert_eq!(rep.replaced, vec![bp.to_string()]);
        assert_eq!(rep.recreated, vec![bp.to_string()]);
        assert!(!rep.all_present());
        assert!(std::fs::symlink_metadata(&bait)
            .unwrap()
            .file_type()
            .is_file());
        assert_eq!(std::fs::read_to_string(&bait).unwrap(), "BAIT");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "THEIRS");
    }

    #[test]
    fn restore_never_creates_through_a_dangling_link() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("would-be-created");
        let bait = dir.path().join("unload.signal");
        std::os::unix::fs::symlink(&target, &bait).unwrap();
        let bp = bait.to_str().unwrap();
        let rep = restore_paths([(bp, "BAIT")].into_iter());
        assert_eq!(rep.replaced, vec![bp.to_string()]);
        assert!(!target.exists(), "nothing written where the link pointed");
        assert_eq!(std::fs::read_to_string(&bait).unwrap(), "BAIT");
    }

    #[test]
    fn restored_bait_is_0644_and_existing_dirs_keep_their_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o751)).unwrap();
        let bait = dir.path().join("kill_switch.conf");
        let fresh = dir.path().join("run/pause.flag");
        let (bp, fp) = (bait.to_str().unwrap(), fresh.to_str().unwrap());
        let rep = restore_paths([(bp, "A"), (fp, "B")].into_iter());
        assert_eq!(rep.recreated.len(), 2);
        let mode =
            |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&bait), 0o644);
        assert_eq!(mode(&fresh), 0o644);
        assert_eq!(
            mode(dir.path()),
            0o751,
            "an existing directory is not chmodded"
        );
        assert_eq!(
            mode(&dir.path().join("run")),
            0o700,
            "a missing one is created closed"
        );
    }

    /// External audit FIMR-008: the `/run` baits are gone after every
    /// reboot; the boot id tells that from a deletion within one boot.
    #[test]
    fn a_reboot_is_told_from_a_restart_by_the_boot_id() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        assert!(boot_changed(d, "aaaa"), "no record: as after a reboot");
        write_boot_id(d, "aaaa").unwrap();
        assert!(!boot_changed(d, "aaaa"), "same boot: a restart");
        assert!(boot_changed(d, "bbbb"), "new boot id: a reboot");
        // a link planted at the record's name is replaced, not followed
        let victim = d.join("victim");
        std::fs::write(&victim, "KEEP").unwrap();
        std::fs::remove_file(d.join(BOOT_ID_FILE)).unwrap();
        std::os::unix::fs::symlink(&victim, d.join(BOOT_ID_FILE)).unwrap();
        write_boot_id(d, "cccc").unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "KEEP");
        assert!(!boot_changed(d, "cccc"));

        let rep = |recreated: &[&str]| HoneypotIntegrityReport {
            total: 10,
            present: 10 - recreated.len(),
            recreated: recreated.iter().map(|s| s.to_string()).collect(),
            failed: Vec::new(),
            replaced: Vec::new(),
        };
        let volatile = rep(&[
            "/run/northnarrow/pause.flag",
            "/run/northnarrow/unload.signal",
        ]);
        assert!(volatile.only_volatile_after_reboot(true));
        assert!(
            !volatile.only_volatile_after_reboot(false),
            "same boot: deleted"
        );
        assert!(!rep(&["/etc/northnarrow/kill_switch.conf"]).only_volatile_after_reboot(true));
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
