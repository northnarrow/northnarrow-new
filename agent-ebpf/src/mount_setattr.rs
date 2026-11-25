//! Lot 1.1 (the review of #569, F1b): a change of a mount's propagation
//! signalled as the kernel makes it — `mount_setattr(2)`'s among them.
//!
//! `mount_setattr(2)` has no LSM hook, and `do_mount_setattr()` (the one
//! function with the resolved path) is inlined on 5.15 and 6.18: nothing
//! refuses it. Every propagation change the kernel makes — `mount(2)`'s
//! `MS_SHARED`, `MS_PRIVATE`, `MS_SLAVE`, `MS_UNBINDABLE` after the
//! `sb_mount` hook, `mount_setattr(2)`'s `MOUNT_ATTR_PROPAGATION` (one call
//! per mount of an `AT_RECURSIVE` change), and `umount_tree()`'s on every
//! mount it takes — goes through `change_mnt_propagation(struct mount *,
//! int)`, a function of `fs/pnode.c` that `fs/namespace.c` calls (never
//! inlined there). This `fentry` reads only the kernel's own `struct
//! mount` — never the caller's memory (an `fmod_ret` on the system call
//! would read its arguments there, a TOCTOU) — and observes: on a mount of
//! a guarded namespace, of a peer group `MOUNT_GROUPS` holds, or on the pin
//! directory's lock or a copy of it, it counts the change
//! (`common::mount_guard::propagation_counts`): the mount guard's refresh
//! is woken within a second (`MOUNT_GUARD_CONF`'s regroup slot) and the
//! agent sees that the change was made (`CONF_PROPAGATED`), where the
//! integrity round signs it (the lock's flags, `mount_attrs_changed`). A
//! mount `umount_tree()` takes has no namespace any more: not counted.
//! Per-mount flags (`MOUNT_ATTR_RDONLY`, `NOEXEC`, `NOSUID`…) do not go
//! through this function: the integrity round's comparison signs them.

use aya_ebpf::{macros::fentry, programs::FEntryContext};

/// `void change_mnt_propagation(struct mount *mnt, int type)` (fentry):
/// observe only.
#[fentry(function = "change_mnt_propagation")]
pub fn mount_guard_propagation(ctx: FEntryContext) -> i32 {
    let mnt: *const u8 = ctx.arg(0);
    if !mnt.is_null() {
        crate::mount_guard::propagation_change(mnt);
    }
    0
}
