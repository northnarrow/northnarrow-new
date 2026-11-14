//! Lot 347 (the alpha's false positives, round 3): a login record written
//! by the packaged unit whose work it is, told by the writer's image and its
//! unit's cgroup — the facts the FIM drain reads while the writer runs.
//!
//! `systemd-update-utmp` writes the boot, shutdown and runlevel records into
//! `/var/log/wtmp`. NN-L-FIM-019 exempts it through the lineage's record of
//! its exec ([`super::rules::OwnClient`]); at the host's shutdown that exec
//! is not always in the lineage when the write is judged (Ubuntu 24.04, lot
//! 344's lab and lot 347's: the agent, still stopping, judged the write
//! before the exec ring was read) and the shutdown record was High, a
//! `would have: KillProcess` of the packaged binary. The drain now reads, at
//! the write of a login record, two facts of the writer, and keeps the
//! unit's name for the write when both hold ([`keep`]):
//!
//! - the image the kernel runs for it (`/proc/<pid>/exe` opened as a file:
//!   its device and inode, no path walked in its mount namespace) is the
//!   host's packaged `systemd-update-utmp` ([`UTMP_IMAGES`], `stat`ed under
//!   the host's root): a copy, a container's file at that path, a renamed
//!   binary are not;
//! - the process is placed in that unit's own cgroup
//!   (`/system.slice/<unit>`, [`UTMP_UNITS`]): systemd puts its unit's
//!   processes there, and only root can move one in.
//!
//! NN-L-FIM-019 has no verdict for such a write ([`unit_of`]); any other
//! writer of wtmp or btmp keeps the High kill (a `dd` appending a record, a
//! copy of the binary, the binary run from a session or another unit). What
//! it trusts: root's units — a root that runs the packaged binary in that
//! unit's cgroup writes the records the unit writes (`reboot`, `shutdown`,
//! `runlevel`: the binary takes no other).

use std::collections::{HashMap, VecDeque};
use std::sync::LazyLock;

use nn_model::telemetry::FimEvent;
use parking_lot::Mutex;

/// The packaged units that write the login records, by unit name.
pub const UTMP_UNITS: &[&str] = &[
    "systemd-update-utmp.service",
    "systemd-update-utmp-runlevel.service",
];

/// Where the distributions install `systemd-update-utmp` (merged `/usr`, and
/// a `/lib` not merged).
pub const UTMP_IMAGES: &[&str] = &[
    "/usr/lib/systemd/systemd-update-utmp",
    "/lib/systemd/systemd-update-utmp",
];

/// The login records whose writes the drain reads the writer of: NN-L-FIM-019's.
pub const LOGIN_RECORDS: &[&str] = &["/var/log/wtmp", "/var/log/btmp"];

/// The review of #556 (F5): the size of a login record, glibc's
/// `struct utmp` (wtmp's and btmp's) on the agent's architecture, which is
/// systemd's: 400 bytes where its session is a `long` and its time a
/// `timeval` (aarch64, s390x, loongarch64), 384 elsewhere (x86_64's 32-bit
/// fields, every 32-bit target).
pub const UTMP_RECORD_LEN: u64 = if cfg!(any(
    target_arch = "aarch64",
    target_arch = "s390x",
    target_arch = "loongarch64"
)) {
    400
} else {
    384
};

/// The review of #556 (F5): `fe`'s write grew its file by whole login
/// records since the drain last read it — what `systemd-update-utmp`
/// writes (a boot, shutdown or runlevel record, appended). The kernel keeps
/// one dirty mark per inode and the drain credits its LAST writer with
/// every write since its last read, so a truncation or a rewrite before the
/// unit's append (`systemctl restart systemd-update-utmp`) was the unit's
/// write: a shrink, a rewrite of the same size or a part of a record is no
/// append, whoever wrote last. Residual: a rewrite of earlier records in
/// place followed by the unit's append within one mark still grows the file
/// by whole records (the drain compares no prefix); it needs root.
pub fn appended_whole_records(fe: &FimEvent) -> bool {
    match (fe.baseline_size, fe.new_size) {
        (Some(before), Some(after)) => after > before && (after - before) % UTMP_RECORD_LEN == 0,
        _ => false,
    }
}

/// The writes kept at most (the oldest out): the decision reads a write's
/// fact right after the drain sent it.
pub const KEPT_WRITES: usize = 256;

/// (the writer's pid, the write's time, the file): one write.
type WriteKey = (u32, u64, String);

#[derive(Default)]
struct Kept {
    units: HashMap<WriteKey, &'static str>,
    order: VecDeque<WriteKey>,
}

static KEPT: LazyLock<Mutex<Kept>> = LazyLock::new(Default::default);

fn key(fe: &FimEvent) -> WriteKey {
    (fe.modifier_pid, fe.timestamp_ns, fe.path.clone())
}

/// The packaged unit a writer is, from its facts: `service`, the unit its
/// placing cgroup names (`crate::posture::daemon_data::system_service`), and
/// whether its image is one of the host's [`UTMP_IMAGES`] (device and inode).
pub fn unit_writer(service: Option<&str>, packaged_image: bool) -> Option<&'static str> {
    if !packaged_image {
        return None;
    }
    let service = service?;
    UTMP_UNITS.iter().copied().find(|u| *u == service)
}

/// The drain's call: the write `fe` was made by the packaged `unit`.
pub fn keep(fe: &FimEvent, unit: &'static str) {
    let k = key(fe);
    let mut kept = KEPT.lock();
    if kept.units.insert(k.clone(), unit).is_none() {
        kept.order.push_back(k);
    }
    while kept.order.len() > KEPT_WRITES {
        if let Some(old) = kept.order.pop_front() {
            kept.units.remove(&old);
        }
    }
}

/// The packaged unit the drain found the writer of `fe` to be, if it did.
pub fn unit_of(fe: &FimEvent) -> Option<&'static str> {
    KEPT.lock().units.get(&key(fe)).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_facts_name_the_unit() {
        let unit = Some("systemd-update-utmp.service");
        assert_eq!(unit_writer(unit, true), unit);
        assert_eq!(
            unit_writer(Some("systemd-update-utmp-runlevel.service"), true),
            Some("systemd-update-utmp-runlevel.service")
        );
        // the packaged image in another unit, a session's scope, no cgroup
        assert_eq!(unit_writer(Some("cron.service"), true), None);
        assert_eq!(unit_writer(None, true), None);
        // another image in the unit's cgroup
        assert_eq!(unit_writer(unit, false), None);
    }

    #[test]
    fn the_kept_writes_are_bounded() {
        let fe = |pid: u32| FimEvent {
            timestamp_ns: 347,
            path: "/var/log/wtmp".into(),
            op: nn_model::telemetry::FimOp::Modified,
            new_sha256: None,
            baseline_sha256: None,
            new_size: None,
            baseline_size: None,
            modifier_exe: None,
            modifier_pid: pid,
            modifier_uid: 0,
            modifier_comm: "systemd-update-".into(),
            dest_path: None,
            child_truncated: false,
            wide_coverage: false,
            owner_uid: None,
            reader_dac_capable: false,
            capability: None,
            attrs: None,
            file_key: None,
            is_dir: false,
            moved_in: false,
            appends_only: false,
            truncated_by_another: false,
            unchanged_since_read: false,
        };
        keep(&fe(34_700), "systemd-update-utmp.service");
        assert_eq!(unit_of(&fe(34_700)), Some("systemd-update-utmp.service"));
        assert_eq!(unit_of(&fe(34_701)), None);
        for pid in 0..KEPT_WRITES as u32 {
            keep(&fe(40_000 + pid), "systemd-update-utmp.service");
        }
        assert_eq!(unit_of(&fe(34_700)), None, "the oldest went out");
    }
}
