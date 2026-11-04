//! Lot 273d (the review of #492): the drop-ins of our own units'
//! directories made inside a trusted-installer window, judged at its close.
//!
//! Outside a window those directories refuse a new entry (NOCREATE);
//! inside one an operator's tooling may leave one — a `set-property` writes
//! `50-<Property>.conf` under `system.control` — and it stays after the
//! window. systemd applies it at its next reload (the agent asks for one,
//! an attacker can provoke one) and at the unit's next start. At the
//! window's close each such drop-in, made or changed since the window
//! opened, is judged as the host's are (`crate::host_dropins`) against its
//! own unit's floors and semantics: a harmful one is moved to the
//! quarantine — these are our units' own files, not the host's — the move
//! is in the window's signed close record, and systemd reloads (at most
//! one a [`crate::systemd_reload::MIN_INTERVAL`]). The drop-ins
//! `install.sh` lays down are known by their content and left.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::host_dropins::{breaks, directives, effective, harms, HostLimits, Kind, Reach};

/// Where a quarantined drop-in goes.
pub const QUARANTINE_DIR: &str = "/var/lib/northnarrow/quarantine/dropins";

/// Our units' drop-in directories under `root`, and whom each reaches.
pub fn own_dirs(root: &Path) -> [(PathBuf, Reach); 4] {
    [
        (root.join("northnarrow-agent.service.d"), Reach::Agent),
        (root.join("northnarrow-watchdog.service.d"), Reach::Watchdog),
        (root.join("northnarrow-.service.d"), Reach::Services),
        // lot 273d: the units' slice of their own
        (root.join("northnarrow.slice.d"), Reach::OurSlice),
    ]
}

/// One drop-in moved, or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moved {
    pub from: PathBuf,
    pub to: Option<PathBuf>,
    pub why: String,
    pub error: Option<String>,
}

impl Moved {
    pub fn detail(&self) -> String {
        match (&self.to, &self.error) {
            (Some(to), None) => format!(
                "{}: {}; moved to {}",
                self.from.display(),
                self.why,
                to.display()
            ),
            (_, e) => format!(
                "{}: {}; NOT moved ({})",
                self.from.display(),
                self.why,
                e.as_deref().unwrap_or("?")
            ),
        }
    }
}

/// The directory an `EnvironmentFile=` of our units may name: our own
/// configuration, protected (the review of #497, D4 — a file anywhere else
/// can change after the judgment, outside any window).
pub const ENV_FILE_DIR: &str = "/etc/northnarrow/";

/// The judged directory's entry: changed at or after `since`, by its
/// ctime — which no `touch -d` sets back and a new hard link, a rename or
/// a content change all move (the review of #497, D4: the mtime did not
/// hold). An unreadable ctime counts as changed.
fn changed_since(meta: &std::fs::Metadata, since: SystemTime) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(s) = since.duration_since(SystemTime::UNIX_EPOCH) else {
        return true;
    };
    let ct = std::time::Duration::new(
        meta.ctime().max(0) as u64,
        meta.ctime_nsec().clamp(0, 999_999_999) as u32,
    );
    ct >= s
}

/// Why an entry of our directories is quarantined whatever its directives
/// say (the review of #497, D4): not a regular file (a symlink systemd
/// follows to a target outside our directories), a hard link (its content
/// changes through another name), or an `EnvironmentFile=` outside
/// [`ENV_FILE_DIR`].
fn shape_harm(meta: &std::fs::Metadata, from: &Path, text: Option<&str>) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    if meta.file_type().is_symlink() {
        let to = std::fs::read_link(from)
            .map(|t| t.display().to_string())
            .unwrap_or_else(|_| "?".to_string());
        return Some(format!(
            "a symlink to {to}: its target lies outside our directories and changes without a window"
        ));
    }
    if !meta.file_type().is_file() {
        return Some("not a regular file".to_string());
    }
    if meta.nlink() > 1 {
        return Some(format!(
            "a hard link ({} names): its content changes through a name outside our directories",
            meta.nlink()
        ));
    }
    let text = text?;
    effective(directives(text))
        .into_iter()
        .filter(|(k, _)| k == "EnvironmentFile")
        .flat_map(|(_, v)| {
            v.split_whitespace()
                .map(|f| f.trim_start_matches('-').to_string())
                .collect::<Vec<_>>()
        })
        .find(|f| !f.starts_with(ENV_FILE_DIR))
        .map(|f| {
            format!(
                "EnvironmentFile={f} lies outside {ENV_FILE_DIR}: its content changes after the judgment"
            )
        })
}

/// The harmful drop-ins of our units' directories under `roots`, changed
/// at or after `since` (by their ctime; the window's opening at its
/// close, `UNIX_EPOCH` at the integrity round, which judges every one of
/// them again — a drop-in kept at a close stays writable by root), moved
/// into `quarantine` (`now`: the name's stamp). `known`: a drop-in
/// `install.sh` lays down, left. Whatever its directives, a symlink, a
/// hard link and an `EnvironmentFile=` outside [`ENV_FILE_DIR`] are
/// quarantined (the review of #497, D4).
pub fn quarantine(
    roots: &[&Path],
    host: &HostLimits,
    since: SystemTime,
    quarantine: &Path,
    now: u64,
    known: impl Fn(&Path, &[u8]) -> bool,
) -> Vec<Moved> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for root in roots {
        for (dir, reach) in own_dirs(root) {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            if let Ok(canon) = std::fs::canonicalize(&dir) {
                if !seen.insert(canon) {
                    continue;
                }
            }
            let mut files: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
            files.sort();
            for from in files {
                if from.extension().and_then(|x| x.to_str()) != Some("conf") {
                    continue;
                }
                let Ok(meta) = std::fs::symlink_metadata(&from) else {
                    continue;
                };
                if !changed_since(&meta, since) {
                    continue;
                }
                let regular = meta.file_type().is_file();
                let bytes = if regular {
                    std::fs::read(&from).ok()
                } else {
                    None
                };
                if regular && bytes.is_none() {
                    continue;
                }
                if let Some(b) = &bytes {
                    if known(&from, b) && meta_nlink(&meta) == 1 {
                        continue;
                    }
                }
                let text = bytes
                    .as_ref()
                    .map(|b| String::from_utf8_lossy(b).to_string());
                let when = if since == SystemTime::UNIX_EPOCH {
                    "found by the integrity round"
                } else {
                    "made inside the window"
                };
                let why = shape_harm(&meta, &from, text.as_deref())
                    .map(|w| format!("{when}, {w}"))
                    .or_else(|| {
                        effective(directives(text.as_deref()?))
                            .into_iter()
                            .find_map(|(k, v)| {
                                harms(reach, &k, &v, host)
                                    .map(|w| (k.clone(), v.clone(), w, Kind::Harmful))
                                    .or_else(|| {
                                        breaks(&k, &v).map(|w| (k, v, w, Kind::BreaksAgent))
                                    })
                            })
                            .map(|(k, v, w, _)| format!("{when}, sets {k}={v}: {w}"))
                    });
                let Some(why) = why else {
                    continue;
                };
                let name: String = from
                    .to_string_lossy()
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                            c
                        } else {
                            '_'
                        }
                    })
                    .collect();
                let to = quarantine.join(format!("{now}-{name}"));
                // a symlink is kept as its target's name, never followed
                let keep = bytes.clone().unwrap_or_else(|| {
                    format!(
                        "symlink -> {}\n",
                        std::fs::read_link(&from)
                            .map(|t| t.display().to_string())
                            .unwrap_or_default()
                    )
                    .into_bytes()
                });
                let moved = std::fs::create_dir_all(quarantine)
                    .and_then(|()| std::fs::write(&to, &keep))
                    .and_then(|()| std::fs::remove_file(&from));
                out.push(match moved {
                    Ok(()) => Moved {
                        from,
                        to: Some(to),
                        why,
                        error: None,
                    },
                    Err(e) => {
                        let _ = std::fs::remove_file(&to);
                        Moved {
                            from,
                            to: None,
                            why,
                            error: Some(e.to_string()),
                        }
                    }
                });
            }
        }
    }
    out
}

fn meta_nlink(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.nlink()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> HostLimits {
        HostLimits {
            mem_total: 16 << 30,
            tasks_max: 4_194_304,
            cpus: vec![0, 1, 2, 3],
            ..Default::default()
        }
    }

    #[test]
    fn a_harmful_drop_in_made_inside_the_window_is_moved_and_the_rest_left() {
        let root = tempfile::tempdir().unwrap();
        let q = tempfile::tempdir().unwrap();
        let since = SystemTime::now() - std::time::Duration::from_secs(5);
        let ag = root.path().join("northnarrow-agent.service.d");
        let wd = root.path().join("northnarrow-watchdog.service.d");
        std::fs::create_dir_all(&ag).unwrap();
        std::fs::create_dir_all(&wd).unwrap();
        // below the agent's floor: moved
        std::fs::write(ag.join("50-MemoryMax.conf"), "[Service]\nMemoryMax=4K\n").unwrap();
        // the watchdog's own 64M is not below ITS floor: left
        std::fs::write(wd.join("50-MemoryMax.conf"), "[Service]\nMemoryMax=64M\n").unwrap();
        // install.sh's: left
        std::fs::write(ag.join("10-known.conf"), "[Service]\nMemoryMax=4K\n").unwrap();
        let r = quarantine(
            &[root.path()],
            &host(),
            since,
            q.path(),
            1700000000,
            |p, _| p.ends_with("10-known.conf"),
        );
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0]
            .detail()
            .contains("50-MemoryMax.conf: made inside the window, sets MemoryMax=4K"));
        assert!(!ag.join("50-MemoryMax.conf").exists());
        assert!(wd.join("50-MemoryMax.conf").exists());
        assert!(ag.join("10-known.conf").exists());
        assert_eq!(std::fs::read_dir(q.path()).unwrap().count(), 1);
        // a drop-in changed before the window is not judged here
        std::fs::write(ag.join("60-old.conf"), "[Service]\nMemoryMax=4K\n").unwrap();
        let later = SystemTime::now() + std::time::Duration::from_secs(60);
        assert!(quarantine(&[root.path()], &host(), later, q.path(), 1, |_, _| false).is_empty());
    }

    /// The review of #497 (D4): an mtime set back (`touch -d`) does not
    /// hide a drop-in made inside the window — its ctime selects it.
    #[test]
    fn an_mtime_set_back_does_not_hide_a_drop_in() {
        let root = tempfile::tempdir().unwrap();
        let q = tempfile::tempdir().unwrap();
        let ag = root.path().join("northnarrow-agent.service.d");
        std::fs::create_dir_all(&ag).unwrap();
        let since = SystemTime::now() - std::time::Duration::from_secs(5);
        let f = ag.join("50-MemoryMax.conf");
        std::fs::write(&f, "[Service]\nMemoryMax=4K\n").unwrap();
        let old = std::fs::FileTimes::new()
            .set_modified(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000));
        std::fs::File::options()
            .write(true)
            .open(&f)
            .unwrap()
            .set_times(old)
            .unwrap();
        assert!(std::fs::metadata(&f).unwrap().modified().unwrap() < since);
        let r = quarantine(&[root.path()], &host(), since, q.path(), 1, |_, _| false);
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(!f.exists());
    }

    /// The review of #497 (D4): a symlink, a hard link and an
    /// `EnvironmentFile=` outside /etc/northnarrow are quarantined whatever
    /// they set; the symlink's target is never written or followed.
    #[test]
    fn a_link_or_an_outside_environment_file_is_quarantined() {
        let root = tempfile::tempdir().unwrap();
        let q = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let ag = root.path().join("northnarrow-agent.service.d");
        std::fs::create_dir_all(&ag).unwrap();
        let since = SystemTime::now() - std::time::Duration::from_secs(5);
        let target = outside.path().join("x.conf");
        std::fs::write(&target, "[Service]\nMemoryMax=2G\n").unwrap();
        std::os::unix::fs::symlink(&target, ag.join("50-link.conf")).unwrap();
        let shared = outside.path().join("shared.conf");
        std::fs::write(&shared, "[Service]\nMemoryMax=2G\n").unwrap();
        std::fs::hard_link(&shared, ag.join("51-hard.conf")).unwrap();
        std::fs::write(
            ag.join("52-env.conf"),
            "[Service]\nEnvironmentFile=-/var/tmp/nn.env\n",
        )
        .unwrap();
        std::fs::write(
            ag.join("53-ours.conf"),
            "[Service]\nEnvironmentFile=/etc/northnarrow/agent.env\nMemoryMax=2G\n",
        )
        .unwrap();
        let r = quarantine(&[root.path()], &host(), since, q.path(), 7, |_, _| false);
        let why: Vec<String> = r.iter().map(Moved::detail).collect();
        assert_eq!(r.len(), 3, "{why:#?}");
        assert!(
            why[0].contains("50-link.conf: made inside the window, a symlink to"),
            "{why:#?}"
        );
        assert!(
            why[1].contains("51-hard.conf: made inside the window, a hard link (2 names)"),
            "{why:#?}"
        );
        assert!(
            why[2].contains("EnvironmentFile=/var/tmp/nn.env lies outside /etc/northnarrow/"),
            "{why:#?}"
        );
        assert!(r.iter().all(|m| m.to.is_some()), "{why:#?}");
        // the link's target untouched; ours (under /etc/northnarrow) kept
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "[Service]\nMemoryMax=2G\n"
        );
        assert!(shared.exists());
        assert!(ag.join("53-ours.conf").exists());
        let kept: Vec<String> = std::fs::read_dir(q.path())
            .unwrap()
            .flatten()
            .map(|e| std::fs::read_to_string(e.path()).unwrap())
            .collect();
        assert!(
            kept.iter().any(|k| k.starts_with("symlink -> ")),
            "{kept:?}"
        );
    }
}
