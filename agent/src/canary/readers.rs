//! External audit DEC-005: the programs whose read of a File or Credential
//! canary is recorded, not killed.
//!
//! A canary of those two types sits where a reader of the whole tree opens
//! it too: a backup run, an anti-malware scan, a desktop indexer, a sync
//! agent. Killing that process tree on every scheduled run broke the backup
//! and told the operator nothing new. The trip is still the canary's: the
//! access is in the signed `canary_access.jsonl` chain and the K5 rule
//! records it (High); only the kill is withheld.
//!
//! A reader is recognised by what the kernel executed (`/proc/<pid>/exe`,
//! or the script an interpreter runs), in a root-owned system tree —
//! [`crate::posture::lineage::ExecIdentity::is_client`] — never by `comm`,
//! which a process sets for itself: a `restic` copied to `/tmp`, or a
//! process that names itself `restic`, is not one.
//!
//! Built in: dedicated backup, anti-malware, indexing and sync programs.
//! Generic tools — `tar`, `rsync`, `cp`, `cat`, `rclone` — are not: they are
//! what an intruder collects and stages data with. An operator whose backup
//! runs one of them adds it, signed, in `canary-readers.local`
//! (`nn-admin config overlay set canary-readers`), knowing that it then
//! reads every canary without a kill.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{anyhow, Result};

use crate::posture::lineage::{in_system_tree, AuthSessionTracker};

/// Programs that read whole trees by design: an entry is a program name
/// (the exe's basename for a binary, the script's for an interpreter) or a
/// tree ending in `/` that only that program installs.
pub const CANARY_READERS: &[&str] = &[
    // backup
    "restic",
    "borg",
    "kopia",
    "duplicity",
    "rdiff-backup",
    "bacula-fd",
    "bareos-fd",
    "urbackupclientbackend",
    // anti-malware
    "clamscan",
    "clamd",
    // desktop indexers
    "tracker-miner-fs-3",
    "tracker-extract-3",
    "baloo_file",
    "baloo_file_extractor",
    // sync
    "syncthing",
];

/// Default path of the operator's overlay.
pub const CANARY_READERS_LOCAL: &str = "/etc/northnarrow/canary-readers.local";

/// Entry shape of `canary-readers.local`: a program name (no `/`, one
/// token) or an absolute tree ending in `/` inside a root-owned system tree.
pub fn validate_reader(entry: &str) -> Result<()> {
    if entry.is_empty() || entry.split_whitespace().count() != 1 {
        return Err(anyhow!(
            "canary reader entries are one whitespace-free token (got `{entry}`)"
        ));
    }
    if entry.contains('/') && !(entry.ends_with('/') && in_system_tree(entry)) {
        return Err(anyhow!(
            "a canary reader is a program name or a system tree ending in `/` \
             (/usr/, /opt/, …) — got `{entry}`"
        ));
    }
    Ok(())
}

/// The readers the K5 File and Credential rules spare, and how they tell
/// one: the built-in list, the operator's signed additions, and the
/// process-lineage cache that knows what a pid executed.
#[derive(Clone, Default)]
pub struct CanaryReaders {
    extra: BTreeSet<String>,
    identity: Option<AuthSessionTracker>,
}

impl CanaryReaders {
    /// No identity source: nothing is a reader (tests, early boot).
    pub fn none() -> Self {
        Self::default()
    }

    /// Readers judged through `identity`, with the operator's `extra`
    /// entries added to [`CANARY_READERS`].
    pub fn new(extra: BTreeSet<String>, identity: AuthSessionTracker) -> Self {
        Self {
            extra,
            identity: Some(identity),
        }
    }

    /// Load the operator's additions from `local` — the path the overlay
    /// gate admitted (signed), or one that does not exist. A missing file
    /// adds nothing; a malformed one is refused whole (fail-secure: the
    /// built-in readers only).
    pub fn load(local: &Path, identity: AuthSessionTracker) -> Self {
        let extra = match std::fs::read_to_string(local) {
            Ok(text) => match crate::config::overlay::parse_overlay_text(
                "canary-readers.local",
                &text,
                &validate_reader,
            ) {
                Ok((adds, _disables)) => adds,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path = %local.display(),
                        "canary-readers.local refused — built-in readers only"
                    );
                    BTreeSet::new()
                }
            },
            Err(_) => BTreeSet::new(),
        };
        if !extra.is_empty() {
            tracing::info!(
                readers = ?extra,
                "canary readers added by the signed overlay"
            );
        }
        Self::new(extra, identity)
    }

    /// The executable (or script) `pid` runs when it is a reader, else
    /// `None` — also when what it runs cannot be told any more.
    pub fn reader(&self, pid: u32) -> Option<String> {
        let id = self.identity.as_ref()?.exec_identity(pid)?;
        let mut entries: Vec<&str> = CANARY_READERS.to_vec();
        entries.extend(self.extra.iter().map(String::as_str));
        if !id.is_client(&entries) {
            return None;
        }
        Some(match id.script {
            Some(script) => script,
            None => id.exe.to_string_lossy().into_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker() -> (tempfile::TempDir, AuthSessionTracker) {
        let dir = tempfile::tempdir().unwrap();
        let t = AuthSessionTracker::new(dir.path());
        (dir, t)
    }

    #[test]
    fn a_built_in_reader_is_known_by_what_the_kernel_executed() {
        let (_d, t) = tracker();
        t.ingest_spawn_with_argv(4100, 1, "/usr/bin/restic", &["restic".into()], 1);
        t.ingest_spawn_with_argv(4101, 1, "/tmp/restic", &["restic".into()], 1);
        t.ingest_spawn_with_argv(
            4102,
            1,
            "/usr/bin/python3.11",
            &[
                "/usr/bin/python3".into(),
                "/usr/bin/borg".into(),
                "create".into(),
            ],
            1,
        );
        t.ingest_spawn_with_argv(4103, 1, "/usr/bin/tar", &["tar".into()], 1);
        let r = CanaryReaders::new(BTreeSet::new(), t);
        assert_eq!(r.reader(4100).as_deref(), Some("/usr/bin/restic"));
        assert_eq!(r.reader(4101), None, "a copy outside the system trees");
        assert_eq!(
            r.reader(4102).as_deref(),
            Some("/usr/bin/borg"),
            "a script, by name"
        );
        assert_eq!(r.reader(4103), None, "tar is the operator's to add");
        assert_eq!(r.reader(4199), None, "unknown pid");
        assert_eq!(CanaryReaders::none().reader(4100), None);
    }

    #[test]
    fn the_operator_adds_readers_by_name_or_by_tree() {
        let (_d, t) = tracker();
        t.ingest_spawn_with_argv(4200, 1, "/usr/bin/tar", &["tar".into()], 1);
        t.ingest_spawn_with_argv(4201, 1, "/opt/acme-backup/bin/agent", &["agent".into()], 1);
        let extra: BTreeSet<String> = ["tar".to_string(), "/opt/acme-backup/".to_string()].into();
        let r = CanaryReaders::new(extra, t);
        assert!(r.reader(4200).is_some());
        assert!(r.reader(4201).is_some());
    }

    #[test]
    fn overlay_entries_are_names_or_system_trees() {
        assert!(validate_reader("tar").is_ok());
        assert!(validate_reader("/opt/acme-backup/").is_ok());
        assert!(validate_reader("/home/u/backup/").is_err());
        assert!(validate_reader("/opt/acme-backup/bin/agent").is_err());
        assert!(validate_reader("two words").is_err());
        assert!(validate_reader("").is_err());
    }

    #[test]
    fn a_missing_or_malformed_overlay_leaves_the_built_ins() {
        let (d, t) = tracker();
        let r = CanaryReaders::load(&d.path().join("absent.local"), t.clone());
        assert!(r.extra.is_empty());
        let bad = d.path().join("bad.local");
        std::fs::write(&bad, "+tar\n+/home/u/x/\n").unwrap();
        let r = CanaryReaders::load(&bad, t.clone());
        assert!(r.extra.is_empty(), "refused whole");
        let good = d.path().join("good.local");
        std::fs::write(&good, "# the nightly backup\n+tar\n").unwrap();
        let r = CanaryReaders::load(&good, t);
        assert!(r.extra.contains("tar"));
    }
}
