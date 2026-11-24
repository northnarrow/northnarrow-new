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
/// graphs) runs first, out of line (`subtree_takes`, its place look-up
/// `held_at`: inlined, 5.15's verifier went past its million instructions
/// and the call chain past 512 bytes of stack), its verdict folded into
/// the unmount's before the top is judged.
#[test]
fn an_unmount_is_judged_by_the_subtree_it_takes() {
    let e = source("agent-ebpf/src/mount_guard.rs");
    let at = e
        .find("unsafe fn try_sb_umount(")
        .expect("try_sb_umount is gone");
    let hook = &e[at..];
    let hook = &hook[..hook.find("\n}\n").expect("its end")];
    let walk = hook
        .find("let below = subtree_takes(o, real) != 0;")
        .expect("the subtree is not read");
    let top = hook
        .find("if guard != 0 && !q.held {")
        .expect("the top's own check");
    assert!(walk < top, "the walk is folded in before the top");
    assert!(hook.contains("if below {\n            q.held = true;"));
    for (f, sig) in [
        (
            "subtree_takes",
            "fn subtree_takes(o: &Offs, real: *const u8) -> u64 {",
        ),
        (
            "held_at",
            "unsafe fn held_at(o: &Offs, m: *const u8, group: u32) -> u64 {",
        ),
    ] {
        let at = e.find(sig).unwrap_or_else(|| panic!("{f} is gone"));
        let attr = e[..at].trim_end().lines().last().unwrap_or("");
        assert_eq!(attr.trim(), "#[inline(never)]", "{f} must stay out of line");
    }
    let walker = &e[e.find("fn subtree_takes(").unwrap()..];
    assert!(
        walker[..walker.find("\n}\n").unwrap()]
            .contains("below_takes_held(umount_below(&Subtree { o, by_id }, real), by_id != 0)")
    );
    // the tree read is the kernel's: the children and the siblings' links
    let tree = &e[e.find("impl Tree for Subtree").expect("the kernel's tree")..];
    for f in ["o.mnt_mounts", "o.mnt_child", "o.mnt_parent", "below_of("] {
        assert!(tree.contains(f), "{f}");
    }
    // no sixteen-byte array to zero in the place's name: a `memset` call
    let name = &e[e.find("unsafe fn name_of(").unwrap()..];
    let name = &name[..name.find("\n}\n").unwrap()];
    assert!(!name.contains("[0u8; 16]") && name.contains("crate::zero::zero("));
    let c = source("common/src/mount_guard.rs");
    assert!(c.contains("pub const SUBTREE_MAX: u32 = 32;"));
}

/// Lot 359 (the re-check 3 of #567, N4): the judge of a change of
/// propagation that reaches the pin directory's lock is out of line and
/// calls nothing that carries a frame of its own — no `decide` (its
/// allow-list call), no record (the ring entry's zeroing call): the lab's
/// first verifier check refused `sb_mount` on 6.8, its chain 576 bytes of
/// 512. It returns the verdict; the hook signs it in its own frame.
#[test]
fn the_lock_judge_is_out_of_line_and_signs_nothing() {
    let e = source("agent-ebpf/src/mount_guard.rs");
    let at = e
        .find("fn lock_propagation(path: *const u8, flags: u64) -> u64 {")
        .expect("lock_propagation is gone");
    let attr = e[..at].trim_end().lines().last().unwrap_or("");
    assert_eq!(attr.trim(), "#[inline(never)]");
    let t = e
        .find("unsafe fn try_lock_propagation(")
        .expect("try_lock_propagation is gone");
    let body = &e[t..];
    let body = &body[..body.find("\n}\n").expect("its end")];
    for call in [
        "decide(",
        "answer(",
        "answer_parts(",
        "emit_attempt(",
        "Query {",
        "query(",
    ] {
        assert!(!body.contains(call), "the out-of-line judge calls {call}");
    }
    assert!(body.contains("lock_verdict("));
    let hook = &e[e.find("unsafe fn try_sb_mount(").unwrap()..];
    let hook = &hook[..hook.find("\n}\n").unwrap()];
    assert!(hook.contains("let r = lock_propagation(path, flags);"));
    assert!(hook.contains("return lock_answer(path, r);"));
}

/// The review of #569 (F1a, F1c): the lock's judge in `sb_mount` reads the
/// namespace before the rule — a recursive `MS_PRIVATE` or `MS_SHARED`
/// above the lock (the re-check of #569, N1) is judged only where the
/// mount changed is PID 1's (`lock_touched` with the
/// target's guard, after `target_of`), the maker's identity is asked only
/// of its own step on the host's lock (`lock_step_at`, never `lock_step`
/// alone), and `systemd-shutdown`'s identity only of its `switch_root()`
/// shape (`lock_shutdown_step`).
#[test]
fn the_lock_judge_reads_the_namespace_before_a_private_change_and_the_makers_step() {
    let e = source("agent-ebpf/src/mount_guard.rs");
    let t = e
        .find("unsafe fn try_lock_propagation(")
        .expect("try_lock_propagation is gone");
    let body = &e[t..];
    let body = &body[..body.find("\n}\n").expect("its end")];
    let widest = body
        .find("lock_touched(flags, on_lock, above, GUARD_HOST)")
        .expect("the widest rule first");
    let target = body.find("target_of(o, at)").expect("the target's guard");
    let by_ns = body
        .find("lock_touched(flags, on_lock, above, guard)")
        .expect("the rule by the target's namespace");
    assert!(widest < target && target < by_ns, "the order of the rule");
    assert!(body.contains("lock_step_at(flags, on_lock, guard) && lock_maker_now()"));
    assert!(body.contains("lock_shutdown_step(flags, on_lock) && shutdown_stage()"));
    assert!(
        !body.contains("lock_step(flags)"),
        "the maker's step anywhere"
    );
}

/// The review of #569's fix round (lab, 5.15): `spread`'s slave carried
/// across its loop as an `Option<G::M>` started as `None`, whose payload is
/// never written — the BPF back end loaded it before it tested the tag
/// (a select), and 5.15's verifier refused `sb_mount` ("invalid read from
/// stack"; 6.5 and later allow the read for a privileged loader, so 6.8
/// and 7.0 loaded it). The walks the eBPF inlines carry no `Option` in a
/// mutable binding: a value always written, and a flag.
#[test]
fn the_mount_walks_carry_no_option_across_a_loop() {
    let s = source("common/src/mount_guard.rs");
    let code = &s[..s.find("#[cfg(test)]").expect("its tests")];
    for (n, line) in code.lines().enumerate() {
        let t = line.trim_start();
        if t.starts_with("//") {
            continue;
        }
        assert!(
            !(t.starts_with("let mut ") && t.contains(": Option<")),
            "common/src/mount_guard.rs:{}: a mutable Option ({t})",
            n + 1
        );
        assert!(
            !(t.starts_with("let mut ") && t.ends_with("= None;")),
            "common/src/mount_guard.rs:{}: a mutable Option ({t})",
            n + 1
        );
    }
}
