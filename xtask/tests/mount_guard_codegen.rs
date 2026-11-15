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
