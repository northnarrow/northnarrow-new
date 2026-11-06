//! Lot 283c — the data directories of the root daemons whose own writes the
//! mass-write arm of `ConfirmedIntrusion` does not count.
//!
//! A server doing its normal job must not sit in ENGAGED. Lot 283a measured
//! containerd and k3s-server replacing their own state files (task
//! directories, CNI results, the kubelet's files) and raising the arm every
//! half minute while k3s ran pods. Such a daemon runs as root, so no
//! ownership tells its files from anyone's: the shipped list
//! `configs/daemon-data.v1` names, per systemd unit, the directories that
//! are its own, and the operator adds entries in the signed mass-write
//! overlay (`mass-write-carveout.local`, lines `+<unit>.service <dir>/`).
//!
//! The kernel tags each listed directory ([`DaemonData::dirs`]: the tag is
//! the directory's index) and tells, for every crossing of the mass-write
//! counters, whether every file the window counted lay in one tagged
//! directory (`common::wire::open_sensor::own_data`). The posture then
//! leaves the crossing out only when the writer's cgroup is one of the
//! units of that directory (`/system.slice/<unit>`): a root process outside
//! the unit, or the unit writing anywhere else, still counts. The counters
//! themselves count everything, and the ransomware tracker (NN-L-IMP-001)
//! reads every crossing.
//!
//! Format, one entry per line, `#` starts a comment:
//!
//! ```text
//! <unit>.service <directory>/
//! ```
//!
//! A unit may name several directories and a directory several units. A
//! directory is refused when it is too broad for the mass-write overlay
//! (`/`, a top-level directory, a user's tree, a shared tree), and when it
//! lies inside another listed directory or holds one: the kernel's tag is
//! one directory's.

use std::path::Path;

use crate::config::overlay::{self, DefaultsSource, Shipped};
use crate::content_host::ContentHost;
use crate::posture::mass_write_overlay::{fold_slashes, too_broad};
use common::wire::open_sensor::own_data;

/// Deploy location of the list.
pub const DAEMON_DATA_V1: &str = "/etc/northnarrow/daemon-data.v1";
/// The shipped list, built in.
pub const BUILTIN_DAEMON_DATA_V1: &str =
    include_str!(concat!(env!("NN_REPO_ROOT"), "/configs/daemon-data.v1"));
/// SHA-256 of every `daemon-data.v1` an earlier release shipped.
pub const EARLIER_DAEMON_DATA_V1_SHA256: &[&str] = &[];
/// The shipped `daemon-data.v1` (built-in copy, earlier ones).
pub const DAEMON_DATA_SHIPPED: Shipped<'static> =
    Shipped::new(BUILTIN_DAEMON_DATA_V1, EARLIER_DAEMON_DATA_V1_SHA256);

/// A list's entry: a unit and its directory (folded, final `/`).
pub type Entry = (String, String);

/// A refused line: its 1-based number and why.
pub type Refused = (usize, String);

/// One listed directory (folded, with its final `/`) and the units whose
/// own data it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonDir {
    pub dir: String,
    pub units: Vec<String>,
}

/// The listed directories; a directory's tag is its index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DaemonData {
    dirs: Vec<DaemonDir>,
}

/// A systemd service name: `<name>.service`, the name of letters, digits
/// and `:_.@\-` (systemd's unit-name characters), not empty.
fn valid_unit(unit: &str) -> bool {
    unit.len() <= 255
        && unit
            .strip_suffix(".service")
            .is_some_and(|name| !name.is_empty() && !name.starts_with('.'))
        && unit
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":_.@\\-".contains(&b))
}

/// One line: `Ok(None)` for a blank or comment line, `Ok(Some((unit,
/// directory)))` for an entry (the directory folded, with its final `/`; a
/// leading `+`, the overlay's directive, allowed), `Err` with the reason,
/// the entry named, for a refused one.
pub fn parse_entry(raw: &str) -> Result<Option<Entry>, String> {
    let line = raw.split_once('#').map_or(raw, |(before, _)| before).trim();
    if line.is_empty() {
        return Ok(None);
    }
    let line = line.strip_prefix('+').unwrap_or(line).trim();
    let mut words = line.split_whitespace();
    let (Some(unit), Some(dir), None) = (words.next(), words.next(), words.next()) else {
        return Err(format!(
            "`{line}`: a daemon's data directory is `<unit>.service <directory>/`"
        ));
    };
    if !valid_unit(unit) {
        return Err(format!(
            "`{unit}`: not a systemd service name (`<name>.service`)"
        ));
    }
    if !dir.starts_with('/') {
        return Err(format!("`{dir}`: not an absolute directory"));
    }
    let mut folded = fold_slashes(dir);
    if !folded.ends_with('/') {
        folded.push('/');
    }
    too_broad(&folded).map_err(|why| format!("`{dir}`: {why}"))?;
    Ok(Some((unit.to_string(), folded)))
}

/// Whether directory `a` (folded, final `/`) lies in `b` or holds it.
fn nests(a: &str, b: &str) -> bool {
    a != b && (a.starts_with(b) || b.starts_with(a))
}

impl DaemonData {
    /// The list of `entries` (unit, folded directory): a directory named
    /// again adds its unit; the refused entries, each with why — a
    /// directory inside another or holding one, and past the kernel's
    /// [`own_data::UNIT_TAGS`] directories.
    pub fn build(entries: impl IntoIterator<Item = (String, String)>) -> (Self, Vec<String>) {
        let mut data = DaemonData::default();
        let mut refused = Vec::new();
        for (unit, dir) in entries {
            if let Some(d) = data.dirs.iter_mut().find(|d| d.dir == dir) {
                if !d.units.contains(&unit) {
                    d.units.push(unit);
                }
                continue;
            }
            if let Some(other) = data.dirs.iter().find(|d| nests(&dir, &d.dir)) {
                refused.push(format!(
                    "`{unit} {dir}`: nests with `{}` — a listed directory may not lie in \
                     another or hold one",
                    other.dir
                ));
                continue;
            }
            if data.dirs.len() as u32 >= own_data::UNIT_TAGS {
                refused.push(format!(
                    "`{unit} {dir}`: more than {} directories",
                    own_data::UNIT_TAGS
                ));
                continue;
            }
            data.dirs.push(DaemonDir {
                dir,
                units: vec![unit],
            });
        }
        (data, refused)
    }

    /// The entries of a list's text, and its refused lines (1-based line
    /// number, reason).
    pub fn parse_text(text: &str) -> (Vec<Entry>, Vec<Refused>) {
        let mut entries = Vec::new();
        let mut refused = Vec::new();
        for (i, raw) in text.lines().enumerate() {
            match parse_entry(raw) {
                Ok(Some(e)) => entries.push(e),
                Ok(None) => {}
                Err(why) => refused.push((i + 1, why)),
            }
        }
        (entries, refused)
    }

    /// The list in force: the shipped entries (`path` when it is the
    /// shipped copy, else the built-in one: [`overlay::load_defaults`],
    /// which says why) and then the overlay's `extras`
    /// (`mass_write_overlay::load_daemon_data_extras`). A refused entry is
    /// an ERROR for the shipped list, a WARN for the overlay's; its
    /// directory's writes count.
    pub fn load<H: ContentHost>(
        path: &Path,
        extras: Vec<(String, String)>,
    ) -> (Self, DefaultsSource) {
        let (shipped, source) = overlay::load_defaults::<H, _>(
            "daemon-data",
            path,
            DAEMON_DATA_SHIPPED,
            |label, text| {
                let (entries, refused) = Self::parse_text(text);
                for (lineno, why) in &refused {
                    tracing::error!(list = label, lineno, reason = %why, "daemon-data: entry refused");
                }
                entries
            },
        );
        let (data, refused) = Self::build(shipped.into_iter().chain(extras));
        for why in &refused {
            tracing::warn!(
                reason = %why,
                "daemon-data: directory refused — writes there count toward the mass-write arm"
            );
        }
        tracing::info!(
            directories = data.dirs.len(),
            "daemon-data: the daemons' own data directories (lot 283c) — their own writes there \
             do not raise the mass-write arm"
        );
        (data, source)
    }

    /// The listed directories, in tag order.
    pub fn dirs(&self) -> &[DaemonDir] {
        &self.dirs
    }

    /// The units of the directory an own-data code names
    /// (`own_data::UNIT_BASE` + its tag); `None` for any other code.
    pub fn units_of(&self, code: u8) -> Option<&[String]> {
        let tag = code.checked_sub(own_data::UNIT_BASE)?;
        self.dirs.get(usize::from(tag)).map(|d| d.units.as_slice())
    }
}

/// The systemd service whose cgroup `cgroup` (a cgroup path, as
/// `/proc/<pid>/cgroup` places a process) is: `/system.slice/<unit>.service`,
/// or one in a slice below `system.slice`
/// (`/system.slice/system-postgresql.slice/postgresql@16-main.service`, a
/// template's instance) — never a scope (a session's, a container's), a
/// sub-cgroup a service made, nor anything outside `system.slice`.
pub fn system_service(cgroup: &str) -> Option<&str> {
    let rest = cgroup.strip_prefix("/system.slice/")?;
    let (slices, unit) = match rest.rsplit_once('/') {
        Some((slices, unit)) => (Some(slices), unit),
        None => (None, rest),
    };
    if !valid_unit(unit) {
        return None;
    }
    if let Some(slices) = slices {
        if !slices
            .split('/')
            .all(|s| s.len() > ".slice".len() && s.ends_with(".slice"))
        {
            return None;
        }
    }
    Some(unit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(text: &str) -> Vec<(String, String)> {
        let (e, refused) = DaemonData::parse_text(text);
        assert!(refused.is_empty(), "{refused:?}");
        e
    }

    /// The shipped list loads whole: every line an entry, no directory
    /// nested in another, the k3s directories shared by its two units.
    #[test]
    fn the_shipped_list_loads() {
        let (data, refused) = DaemonData::build(entries(BUILTIN_DAEMON_DATA_V1));
        assert!(refused.is_empty(), "{refused:?}");
        let units = |dir: &str| {
            data.dirs()
                .iter()
                .find(|d| d.dir == dir)
                .map(|d| d.units.clone())
                .unwrap_or_default()
        };
        assert_eq!(units("/var/lib/containerd/"), vec!["containerd.service"]);
        assert_eq!(units("/var/lib/docker/"), vec!["docker.service"]);
        assert_eq!(
            units("/var/lib/rancher/"),
            vec!["k3s.service", "k3s-agent.service"]
        );
        assert!(units("/var/lib/kubelet/").contains(&"kubelet.service".to_string()));
        assert!(units("/var/lib/kubelet/").contains(&"k3s.service".to_string()));
        assert_eq!(units("/var/lib/etcd/"), vec!["etcd.service"]);
    }

    /// An entry is a service and a directory; what the mass-write overlay
    /// refuses as too broad is refused here too, each named.
    #[test]
    fn entries_are_a_service_and_a_narrow_directory() {
        assert_eq!(
            parse_entry("+containerd.service //var/lib/containerd # its state"),
            Ok(Some((
                "containerd.service".to_string(),
                "/var/lib/containerd/".to_string()
            )))
        );
        assert_eq!(parse_entry("  # only a comment"), Ok(None));
        for (line, why) in [
            (
                "containerd /var/lib/containerd/",
                "not a systemd service name",
            ),
            (
                "containerd.scope /var/lib/containerd/",
                "not a systemd service name",
            ),
            (".service /var/lib/x/", "not a systemd service name"),
            ("a/b.service /var/lib/x/", "not a systemd service name"),
            ("x.service var/lib/x/", "not an absolute directory"),
            ("x.service /var/lib/x/ extra", "<unit>.service <directory>/"),
            ("/var/lib/x/", "<unit>.service <directory>/"),
            ("x.service /", "whole filesystem"),
            ("x.service /var/", "data root"),
            ("x.service /home/alice/", "whole user's tree"),
            ("x.service /var/tmp/", "`/var/tmp`"),
            ("x.service /var/lib/../../home/", "`..`"),
        ] {
            let e = parse_entry(line).expect_err(line);
            assert!(e.contains(why), "{line}: {e}");
        }
    }

    /// A directory named twice gathers its units; one inside another (or
    /// holding one) is refused, as its kernel tag would mix with the
    /// other's; past the kernel's tags nothing more is listed.
    #[test]
    fn directories_never_nest_and_tags_are_bounded() {
        let e = |u: &str, d: &str| (u.to_string(), d.to_string());
        let (data, refused) = DaemonData::build([
            e("a.service", "/var/lib/a/"),
            e("b.service", "/var/lib/a/"),
            e("c.service", "/var/lib/a/sub/"),
            e("d.service", "/var/lib/"),
            e("e.service", "/var/lib/ab/"),
        ]);
        assert_eq!(data.dirs().len(), 2);
        assert_eq!(data.dirs()[0].units, vec!["a.service", "b.service"]);
        assert_eq!(data.dirs()[1].dir, "/var/lib/ab/");
        assert_eq!(refused.len(), 2, "{refused:?}");
        assert!(refused[0].contains("c.service") && refused[0].contains("nests"));
        assert!(refused[1].contains("d.service") && refused[1].contains("nests"));
        assert_eq!(
            data.units_of(own_data::UNIT_BASE),
            Some(&["a.service".to_string(), "b.service".to_string()][..])
        );
        assert_eq!(
            data.units_of(own_data::UNIT_BASE + 1).map(|u| u.len()),
            Some(1)
        );
        assert_eq!(data.units_of(own_data::UNIT_BASE + 2), None);
        assert_eq!(data.units_of(own_data::SERVICE), None);
        assert_eq!(data.units_of(own_data::CACHE), None);

        let many = (0..own_data::UNIT_TAGS + 2).map(|i| e("x.service", &format!("/srv/d{i}/")));
        let (data, refused) = DaemonData::build(many);
        assert_eq!(data.dirs().len() as u32, own_data::UNIT_TAGS);
        assert_eq!(refused.len(), 2);
        assert!(refused[0].contains("more than"));
    }

    /// A unit's cgroup: `system.slice/<unit>.service`, or an instance in a
    /// slice below it; never a scope, a sub-cgroup, a user's service or a
    /// session.
    #[test]
    fn a_system_service_is_told_by_its_cgroup() {
        assert_eq!(
            system_service("/system.slice/k3s.service"),
            Some("k3s.service")
        );
        assert_eq!(
            system_service("/system.slice/system-postgresql.slice/postgresql@16-main.service"),
            Some("postgresql@16-main.service")
        );
        for not in [
            "/user.slice/user-1000.slice/session-3.scope",
            "/user.slice/user-1000.slice/user@1000.service/app.slice/x.service",
            "/system.slice/docker-0123abcd.scope",
            "/system.slice/containerd.service/payload",
            "/system.slice/run-r1.scope",
            "/system.slice/.slice/x.service",
            "/system.slice/",
            "/system.slice",
            "/kubepods.slice/kubepods-pod1.slice/cri-containerd-1.scope",
            "/",
            "",
        ] {
            assert_eq!(system_service(not), None, "{not}");
        }
    }
}
