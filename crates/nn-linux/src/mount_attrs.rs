//! Lot 357 (the coordinator's `mount_setattr` point): the attributes of the
//! mounts that hold the agent's paths, watched.
//!
//! `mount_setattr(2)` (and `mount(2)`'s remount and propagation changes,
//! which the mount guard lets through: they cover nothing) changes a
//! mount's per-mount options (`ro`, `nosuid`, `noexec`…) and its
//! propagation (`shared:`, `master:`, `unbindable`) — and the kernel has no
//! LSM hook for `mount_setattr(2)`, nor a function every supported kernel
//! keeps for an `fentry` (`do_mount_setattr` is inlined on 5.15 and 6.18).
//! Neither hides a path: a read-only mount makes the agent's writes there
//! fail (each a signed degradation), and a propagation change is what lets
//! a mount made in another namespace reach the host's — which the guard
//! follows whatever its origin (peers and slaves, `reaches`). So the change
//! itself is signed: the integrity round compares, every round, the
//! options and propagation PID 1's table shows for each mount a watched
//! path resolves through (`/`, `/etc`, `/var`, `/run`, `/sys`, the bpffs…)
//! with the first it saw (`mount_attrs_changed`, High).

use std::collections::{BTreeMap, BTreeSet};

/// A mount's attributes in a `mountinfo` line: its per-mount options
/// (field 6) and its optional fields (propagation), in the table's order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attrs {
    pub options: String,
    pub propagation: String,
}

/// `id → (mount point, attributes)` of a `mountinfo` text (a line not in
/// the kernel's shape is skipped: the mount watch judges it).
pub fn attrs_of(text: &[u8]) -> BTreeMap<u64, (String, Attrs)> {
    let mut out = BTreeMap::new();
    for line in String::from_utf8_lossy(text).lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let Some(sep) = f.iter().position(|x| *x == "-") else {
            continue;
        };
        if sep < 6 {
            continue;
        }
        let Ok(id) = f[0].parse::<u64>() else {
            continue;
        };
        out.insert(
            id,
            (
                f[4].to_string(),
                Attrs {
                    options: f[5].to_string(),
                    propagation: f[6..sep].join(" "),
                },
            ),
        );
    }
    out
}

/// The attributes of the watched mounts as first seen.
#[derive(Debug, Default)]
pub struct AttrWatch {
    base: BTreeMap<u64, Attrs>,
}

impl AttrWatch {
    /// The watched mounts (`ids`) of this round's table whose attributes
    /// differ from the first seen: `(mount point, what changed)`. A mount
    /// seen for the first time is its own baseline; one gone is dropped.
    pub fn round(&mut self, text: &[u8], ids: &BTreeSet<u64>) -> Vec<(String, String)> {
        let now = attrs_of(text);
        self.base.retain(|id, _| now.contains_key(id));
        let mut out = Vec::new();
        for id in ids {
            let Some((mp, a)) = now.get(id) else {
                continue;
            };
            match self.base.get(id) {
                None => {
                    self.base.insert(*id, a.clone());
                }
                Some(b) if b == a => {}
                Some(b) => {
                    let mut what = Vec::new();
                    if b.options != a.options {
                        what.push(format!("options {} → {}", b.options, a.options));
                    }
                    if b.propagation != a.propagation {
                        let shown = |p: &str| {
                            if p.is_empty() {
                                "private".to_string()
                            } else {
                                p.to_string()
                            }
                        };
                        what.push(format!(
                            "propagation {} → {}",
                            shown(&b.propagation),
                            shown(&a.propagation)
                        ));
                    }
                    out.push((mp.clone(), what.join(", ")));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = "\
1 0 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
25 1 0:22 / /run rw,nosuid,nodev,noexec,relatime shared:5 - tmpfs tmpfs rw,mode=755
26 1 0:23 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw
";

    /// The coordinator's mount_setattr point: a protected mount made
    /// read-only, made a slave or private, or its options changed, is
    /// reported against the first table seen; an unwatched mount, or the
    /// same attributes, never is.
    #[test]
    fn a_protected_mounts_attributes_changed_are_reported() {
        let ids: BTreeSet<u64> = [1, 25].into_iter().collect();
        let mut w = AttrWatch::default();
        assert!(w.round(TABLE.as_bytes(), &ids).is_empty(), "the baseline");
        assert!(w.round(TABLE.as_bytes(), &ids).is_empty(), "unchanged");
        // /run read-only (mount_setattr MOUNT_ATTR_RDONLY, or a bind remount)
        let ro = TABLE.replace("/run rw,nosuid", "/run ro,nosuid");
        let f = w.round(ro.as_bytes(), &ids);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].0, "/run");
        assert!(
            f[0].1
                .contains("options rw,nosuid,nodev,noexec,relatime → ro,"),
            "{f:?}"
        );
        // / made a slave of its peer group (the propagation path)
        let slave = TABLE.replace("/ rw,relatime shared:1 -", "/ rw,relatime master:1 -");
        let f = w.round(slave.as_bytes(), &ids);
        assert_eq!(
            f,
            vec![(
                "/".to_string(),
                "propagation shared:1 → master:1".to_string()
            )]
        );
        // private
        let private = TABLE.replace(" shared:5 -", " -");
        let f = w.round(private.as_bytes(), &ids);
        assert_eq!(f[0].1, "propagation shared:5 → private");
        // /proc is not watched here: its change is not this watch's
        let proc_ro = TABLE.replace("/proc rw,", "/proc ro,");
        assert!(w.round(proc_ro.as_bytes(), &ids).is_empty());
        // a mount gone and back with a new id is its own new baseline
        let again = TABLE.replace("25 1 0:22", "99 1 0:22");
        let ids2: BTreeSet<u64> = [1, 99].into_iter().collect();
        assert!(w.round(again.as_bytes(), &ids2).is_empty());
    }

    #[test]
    fn a_line_not_in_the_kernels_shape_is_skipped() {
        let a = attrs_of(b"x y z\n1 0 8:1 / / rw - ext4 /dev/sda1 rw\n");
        assert_eq!(a.len(), 1);
        assert_eq!(a[&1].1.propagation, "");
    }
}
