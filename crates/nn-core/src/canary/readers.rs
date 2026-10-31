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

use anyhow::{anyhow, Result};

use crate::config::overlay_auth::Verified;
use crate::posture::host::PostureHost;
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
///
/// R08a (lab PR 250): `H` is the host the lineage cache reads
/// ([`PostureHost`]; the agent's is `LinuxHost`).
#[derive(Clone, Default)]
pub struct CanaryReaders<H: PostureHost> {
    extra: BTreeSet<String>,
    identity: Option<AuthSessionTracker<H>>,
}

impl<H: PostureHost> CanaryReaders<H> {
    /// No identity source: nothing is a reader (tests, early boot).
    pub fn none() -> Self {
        Self::default()
    }

    /// Readers judged through `identity`, with the operator's `extra`
    /// entries added to [`CANARY_READERS`].
    pub fn new(extra: BTreeSet<String>, identity: AuthSessionTracker<H>) -> Self {
        Self {
            extra,
            identity: Some(identity),
        }
    }

    /// Load the operator's additions from `local` — the overlay as the
    /// signed-overlay gate verified it (external audit LLMR-013). None
    /// adds nothing; a malformed one is refused whole (fail-secure: the
    /// built-in readers only).
    pub fn load(local: &Verified, identity: AuthSessionTracker<H>) -> Self {
        let extra = match local.text() {
            Some(text) => match crate::config::overlay::parse_overlay_text(
                "canary-readers.local",
                text,
                &validate_reader,
            ) {
                Ok((adds, _disables)) => adds,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path = ?local.source(),
                        "canary-readers.local refused — built-in readers only"
                    );
                    BTreeSet::new()
                }
            },
            None => BTreeSet::new(),
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
    /// `None` — also when what it runs cannot be told any more. As of
    /// `as_of` (R12b, R-F: the trip's time — a reader that executes
    /// `restic` after the read is no reader; in a judgement the spawn cache
    /// only).
    pub fn reader(&self, pid: u32, as_of: crate::posture::lineage::AsOf) -> Option<String> {
        let id = self.identity.as_ref()?.exec_identity(pid, as_of)?;
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

    use crate::posture::host::testing::TestHost;

    /// R08a (lab PR 250): the readers and their lineage cache on the
    /// portable test host.
    type AuthSessionTracker = crate::posture::lineage::AuthSessionTracker<TestHost>;
    type CanaryReaders = super::CanaryReaders<TestHost>;

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
        assert_eq!(
            r.reader(4100, crate::posture::lineage::AsOf::Now)
                .as_deref(),
            Some("/usr/bin/restic")
        );
        assert_eq!(
            r.reader(4101, crate::posture::lineage::AsOf::Now),
            None,
            "a copy outside the system trees"
        );
        assert_eq!(
            r.reader(4102, crate::posture::lineage::AsOf::Now)
                .as_deref(),
            Some("/usr/bin/borg"),
            "a script, by name"
        );
        assert_eq!(
            r.reader(4103, crate::posture::lineage::AsOf::Now),
            None,
            "tar is the operator's to add"
        );
        assert_eq!(
            r.reader(4199, crate::posture::lineage::AsOf::Now),
            None,
            "unknown pid"
        );
        assert_eq!(
            CanaryReaders::none().reader(4100, crate::posture::lineage::AsOf::Now),
            None
        );
    }

    #[test]
    fn the_operator_adds_readers_by_name_or_by_tree() {
        let (_d, t) = tracker();
        t.ingest_spawn_with_argv(4200, 1, "/usr/bin/tar", &["tar".into()], 1);
        t.ingest_spawn_with_argv(4201, 1, "/opt/acme-backup/bin/agent", &["agent".into()], 1);
        let extra: BTreeSet<String> = ["tar".to_string(), "/opt/acme-backup/".to_string()].into();
        let r = CanaryReaders::new(extra, t);
        assert!(r.reader(4200, crate::posture::lineage::AsOf::Now).is_some());
        assert!(r.reader(4201, crate::posture::lineage::AsOf::Now).is_some());
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
        let content = |text: &str| Verified::Content {
            path: d.path().join("canary-readers.local"),
            text: text.to_string(),
        };
        let r = CanaryReaders::load(&Verified::Missing, t.clone());
        assert!(r.extra.is_empty());
        let r = CanaryReaders::load(&content("+tar\n+/home/u/x/\n"), t.clone());
        assert!(r.extra.is_empty(), "refused whole");
        let r = CanaryReaders::load(&content("# the nightly backup\n+tar\n"), t);
        assert!(r.extra.contains("tar"));
    }

    /// Review of #475: an anti-malware daemon running since before the
    /// agent (the start's scan entered it) is still a reader in a
    /// judgement after 2,100 execs of other processes — the cache keeps a
    /// live process's entry, so CANARY-001's reader exemption holds and
    /// the daemon is not killed at its first read of a canary.
    #[test]
    fn a_daemon_older_than_the_agent_stays_a_reader_after_2100_other_execs() {
        use crate::posture::lineage::AsOf;
        const S: u64 = 1_000_000_000;
        let (dir, t) = tracker();
        let d = dir.path().join("500");
        std::fs::create_dir_all(&d).unwrap();
        crate::posture::host::testing::symlink("/usr/sbin/clamd", d.join("exe")).unwrap();
        std::fs::write(
            d.join("status"),
            "Name:\tclamd\nPid:\t500\nPPid:\t1\nUid:\t0\t0\t0\t0\n",
        )
        .unwrap();
        std::fs::write(
            d.join("stat"),
            "500 (clamd) S 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n",
        )
        .unwrap();
        assert_eq!(t.seed_from_proc(), 1);
        for i in 0..2_100u64 {
            t.ingest_exec(
                10_000 + i as u32,
                1,
                "/usr/bin/true",
                &[],
                (10 + i) * S,
                (10 + i) * S,
                0,
            );
        }
        t.sweep();
        let r = CanaryReaders::new(BTreeSet::new(), t);
        assert_eq!(
            r.reader(500, AsOf::Judged(3_000 * S)).as_deref(),
            Some("/usr/sbin/clamd")
        );
    }

    /// Third review of #475 (X1): an anti-malware daemon started after the
    /// agent that forks and exits (`Type=forking`) — its child reparented to
    /// pid 1 — is a reader once the sweep found its parent gone: CANARY-001's
    /// exemption holds for the daemon that does the reading.
    #[test]
    fn a_daemon_that_forked_after_the_agent_s_start_is_a_reader_once_swept() {
        use crate::posture::lineage::AsOf;
        const S: u64 = 1_000_000_000;
        let (dir, t) = tracker();
        t.ingest_exec(500, 1, "/usr/sbin/clamd", &[], 10 * S, 10 * S, 0);
        let d = dir.path().join("501");
        std::fs::create_dir_all(&d).unwrap();
        crate::posture::host::testing::symlink("/usr/sbin/clamd", d.join("exe")).unwrap();
        std::fs::write(
            d.join("status"),
            "Name:\tclamd\nPid:\t501\nPPid:\t1\nUid:\t0\t0\t0\t0\n",
        )
        .unwrap();
        std::fs::write(
            d.join("stat"),
            "501 (clamd) S 1 501 501 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 1005 0 0\n",
        )
        .unwrap();
        assert_eq!(t.sweep().orphans, 1);
        let r = CanaryReaders::new(BTreeSet::new(), t);
        assert_eq!(
            r.reader(501, AsOf::Judged(20 * S)).as_deref(),
            Some("/usr/sbin/clamd")
        );
    }
}
