//! The review of #567 (lot 357's fix round): the mount guard's allow-list
//! check stays out of line in the eBPF object. Inlined into `decide`, the
//! BPF back end specialised its loop by the point's depth and, on the lab's
//! Ubuntu 22.04 guest (5.15), no kernel's own mount matched any more:
//! fusectl, configfs, binfmt_misc and tracefs mounted back, a chroot's
//! cgroup2, systemd-nspawn's and podman's own mounts were all refused. As
//! its own function (as lot 357 first shipped it) it matches; this keeps it
//! so.

use std::path::Path;

fn source(rel: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

#[test]
fn the_allow_list_check_is_never_inlined_into_the_decision() {
    let s = source("common/src/mount_guard.rs");
    let at = s
        .find("pub fn allowed_kernel_mount(")
        .expect("allowed_kernel_mount is gone: keep the allow-list check out of line");
    let before = &s[..at];
    let attr = before.trim_end().lines().last().unwrap_or("");
    assert_eq!(
        attr.trim(),
        "#[inline(never)]",
        "allowed_kernel_mount must be #[inline(never)] (the eBPF allow-list miscompiled inlined)"
    );
}

/// The re-check 2 of #567 (N3): `sb_umount` reads the subtree an unmount
/// takes — `mount --rbind /sys /mnt/s; umount -l /mnt/s` judged the top
/// only (a copy, at a place nothing is held at) while the kernel took the
/// host's `/sys/fs/bpf` and `/sys/fs/cgroup` through the copies below it,
/// in every slave namespace too: the bpffs lost its last mount. The walk
/// (`common::mount_guard::umount_below`, its host tests the probes'
/// graphs) runs before the top is judged, its verdict folded into the
/// unmount's.
#[test]
fn an_unmount_is_judged_by_the_subtree_it_takes() {
    let e = source("agent-ebpf/src/mount_guard.rs");
    let at = e
        .find("unsafe fn try_sb_umount(")
        .expect("try_sb_umount is gone");
    let hook = &e[at..];
    let hook = &hook[..hook.find("\n}\n").expect("its end")];
    let walk = hook.find("umount_below(").expect("the subtree is not read");
    let verdict = hook.find("below_takes_held(").expect("its verdict");
    let top = hook
        .find("if guard != 0 && !q.held {")
        .expect("the top's own check");
    assert!(verdict < walk && walk < top, "the walk is folded in before the top");
    assert!(hook.contains("if below {\n        q.held = true;"));
    // the tree read is the kernel's: the children and the siblings' links
    let tree = &e[e.find("impl Tree for Subtree").expect("the kernel's tree")..];
    for f in ["o.mnt_mounts", "o.mnt_child", "o.mnt_parent", "below_of("] {
        assert!(tree.contains(f), "{f}");
    }
    let c = source("common/src/mount_guard.rs");
    assert!(c.contains("pub const SUBTREE_MAX: u32 = 32;"));
}
