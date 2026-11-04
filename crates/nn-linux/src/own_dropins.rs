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

/// The harmful drop-ins of our units' directories under `roots`, made or
/// changed at or after `since` (the window's opening), moved into
/// `quarantine` (`now`: the name's stamp). `known`: a drop-in `install.sh`
/// lays down, left.
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
                if !meta.file_type().is_file() || meta.modified().is_ok_and(|m| m < since) {
                    continue;
                }
                let Ok(bytes) = std::fs::read(&from) else {
                    continue;
                };
                if known(&from, &bytes) {
                    continue;
                }
                let text = String::from_utf8_lossy(&bytes);
                let why = effective(directives(&text)).into_iter().find_map(|(k, v)| {
                    harms(reach, &k, &v, host)
                        .map(|w| (k.clone(), v.clone(), w, Kind::Harmful))
                        .or_else(|| breaks(&k, &v).map(|w| (k, v, w, Kind::BreaksAgent)))
                });
                let Some((k, v, w, _)) = why else {
                    continue;
                };
                let why = format!("made inside the window, sets {k}={v}: {w}");
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
                let moved = std::fs::create_dir_all(quarantine)
                    .and_then(|()| std::fs::write(&to, &bytes))
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
        // a drop-in older than the window is not judged here
        std::fs::write(ag.join("60-old.conf"), "[Service]\nMemoryMax=4K\n").unwrap();
        let later = SystemTime::now() + std::time::Duration::from_secs(60);
        assert!(quarantine(&[root.path()], &host(), later, q.path(), 1, |_, _| false).is_empty());
    }
}
