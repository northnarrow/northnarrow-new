//! Lab PR 245: who the ladder acts against, as its signed rows name them.
//!
//! An offender was a PID in the rows (`offenders`), and the INVESTIGATE row
//! of a COMBAT the posture reached named none. The ladder now keeps, for
//! each process it attributes, what identified it when it was attributed —
//! the pid, the starts the capture holds (external audit CMB-004), the
//! executable and the cgroup — and every `combat_stage` row carries them
//! (`offender_details`, in the order of `offenders`). After a NEUTRALIZE
//! nothing of the process is left in `/proc`: the row is the record.
//!
//! Data and its rendering only: `/proc` is read by the actuator
//! (`actuator::read_proc_facts`, the Linux side).

use serde_json::{json, Value};

/// The longest executable or cgroup path a row carries, in bytes. A longer
/// one keeps its end (the file, the unit or container that names it) after
/// a leading `…`. With [`super::LadderConfig::max_offenders`] processes in
/// a row, a path of `PATH_MAX` for each would make rows of megabytes.
pub const MAX_PATH_SHOWN: usize = 512;

/// What `/proc/<pid>` said of a process when the ladder attributed it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcFacts {
    /// `/proc/<pid>/exe` as the kernel resolves it (a ` (deleted)` suffix
    /// kept: the binary was unlinked while it ran). `None` when it could
    /// not be read.
    pub exe: Option<String>,
    /// The cgroup that placed it: the unified hierarchy's (`0::/…`), or
    /// systemd's own on a v1 host.
    pub cgroup: Option<String>,
}

/// The cgroup path a `/proc/<pid>/cgroup` text places the process in: the
/// unified hierarchy (`0::/…`), or systemd's own (`name=systemd`) on a v1
/// host.
pub fn cgroup_path(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .or_else(|| {
            text.lines()
                .find_map(|l| l.split_once(":name=systemd:").map(|(_, p)| p))
        })
}

/// `s` within [`MAX_PATH_SHOWN`] bytes: as it is, or its end after `…`.
pub fn shown(s: &str) -> String {
    if s.len() <= MAX_PATH_SHOWN {
        return s.to_string();
    }
    let mut cut = s.len() - MAX_PATH_SHOWN;
    while !s.is_char_boundary(cut) {
        cut += 1;
    }
    format!("…{}", &s[cut..])
}

/// How an offender joined its episode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// Named by the event that moved the posture to COMBAT: the process
    /// the episode opened against.
    Entry,
    /// Named by a later COMBAT entry while the episode ran (its row says
    /// so: `added`).
    LaterEntry,
    /// Spawned by an offender (lateral spread).
    Spread { parent: u32 },
}

/// An offender as the ladder captured it when it attributed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffenderId {
    pub pid: u32,
    /// `starttime` of `/proc/<pid>/stat` (clock ticks since boot), when the
    /// capture read it.
    pub start_ticks: Option<u64>,
    /// The start its event reported (`CLOCK_MONOTONIC` ns), when known.
    pub start_ns: Option<u64>,
    /// The attributing event's time: it was running then.
    pub seen_ns: Option<u64>,
    /// Its executable and cgroup, read when it was attributed.
    pub facts: ProcFacts,
    pub via: Via,
}

impl OffenderId {
    /// The identity as a signed row carries it.
    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "pid": self.pid,
            "start_ticks": self.start_ticks,
            "start_ns": self.start_ns,
            "seen_ns": self.seen_ns,
            "exe": self.facts.exe,
            "cgroup": self.facts.cgroup,
            "via": match self.via {
                Via::Entry => "entry",
                Via::LaterEntry => "later_entry",
                Via::Spread { .. } => "spread",
            },
        });
        if let Via::Spread { parent } = self.via {
            v["parent"] = Value::from(parent);
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cgroup that places a process: the unified line, or systemd's on
    /// a v1 host; none from a controller's line alone.
    #[test]
    fn the_cgroup_path_of_a_proc_cgroup_text() {
        assert_eq!(
            cgroup_path("0::/system.slice/apache2.service\n"),
            Some("/system.slice/apache2.service")
        );
        assert_eq!(
            cgroup_path("12:pids:/user.slice\n1:name=systemd:/user.slice/session-3.scope\n"),
            Some("/user.slice/session-3.scope")
        );
        assert_eq!(cgroup_path("12:pids:/user.slice\n"), None);
    }

    /// A path past the bound keeps its end, marked; a row stays bounded.
    #[test]
    fn a_long_path_keeps_its_end() {
        let long = format!("/{}/payload", "é".repeat(400));
        let s = shown(&long);
        assert!(s.starts_with('…') && s.ends_with("/payload"), "{s}");
        assert!(s.len() <= MAX_PATH_SHOWN + '…'.len_utf8());
        assert_eq!(shown("/usr/bin/sleep"), "/usr/bin/sleep");
    }

    #[test]
    fn an_identity_renders_how_it_was_attributed() {
        let id = |via| OffenderId {
            pid: 77,
            start_ticks: Some(1234),
            start_ns: None,
            seen_ns: None,
            facts: ProcFacts {
                exe: Some("/tmp/x".into()),
                cgroup: None,
            },
            via,
        };
        let v = id(Via::Spread { parent: 70 }).to_json();
        assert_eq!(v["pid"], 77);
        assert_eq!(v["start_ticks"], 1234);
        assert!(v["start_ns"].is_null() && v["cgroup"].is_null());
        assert_eq!(v["exe"], "/tmp/x");
        assert_eq!(v["via"], "spread");
        assert_eq!(v["parent"], 70);
        let entry = id(Via::Entry).to_json();
        assert_eq!(entry["via"], "entry");
        assert!(entry.get("parent").is_none());
    }
}
