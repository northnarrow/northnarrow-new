//! Fail-open accounting of the anti-tamper deny hooks, shared by the eBPF
//! programs and the agent (lab PR 215, capability C23).
//!
//! A deny hook decides from what it reads in the kernel: the target's
//! tgid, the inode behind a dentry or a file, the map id, the link a file
//! descriptor names. When a read it needs fails, or a position it needs
//! is not known, the hook cannot decide and lets the operation through:
//! an LSM program cannot wait or retry, and refusing every such operation
//! on the host would break it. Until lab PR 215 nothing counted those
//! cases, so an operation the hook let through undecided left no trace.
//! Each one now bumps the per-CPU counter of its hook in the
//! `DENY_FAIL_OPEN` map. The agent sums the counters every few seconds,
//! logs every increase at WARN, writes a signed `deny_fail_open` audit
//! entry and reports the totals in the signed `nn-admin status`.
//!
//! What is not a fail-open, and not counted: a NULL the kernel holds
//! where the hook looks (a negative dentry, the target of a rename that
//! does not exist yet), an fd that names no link (the kernel refuses the
//! command itself), an operation outside the hook's scope.
//!
//! Slot order is wire-stable: append only.

/// Number of counted hooks (map size).
pub const FAIL_OPEN_SLOTS: u32 = 20;

/// Slot of each deny hook in `DENY_FAIL_OPEN`: the agent's `DENY_HOOKS`,
/// then its optional deny hooks, then the `bpf` hook (an observer that
/// also refuses link handles).
pub mod hook {
    pub const TASK_KILL: u32 = 0;
    pub const PTRACE_ACCESS_CHECK: u32 = 1;
    pub const INODE_UNLINK: u32 = 2;
    pub const INODE_RMDIR: u32 = 3;
    pub const INODE_RENAME: u32 = 4;
    pub const INODE_SETATTR: u32 = 5;
    pub const FILE_IOCTL: u32 = 6;
    pub const FILE_OPEN: u32 = 7;
    pub const INODE_CREATE: u32 = 8;
    pub const INODE_MKDIR: u32 = 9;
    pub const INODE_MKNOD: u32 = 10;
    pub const INODE_SYMLINK: u32 = 11;
    pub const INODE_LINK: u32 = 12;
    pub const INODE_SETXATTR: u32 = 13;
    pub const INODE_REMOVEXATTR: u32 = 14;
    pub const BPF_MAP: u32 = 15;
    pub const INODE_SET_ACL: u32 = 16;
    pub const INODE_REMOVE_ACL: u32 = 17;
    pub const FILE_IOCTL_COMPAT: u32 = 18;
    pub const BPF: u32 = 19;
}

/// LSM hook names, indexed by slot (the names `DENY_HOOKS` uses).
pub const FAIL_OPEN_HOOKS: [&str; FAIL_OPEN_SLOTS as usize] = [
    "task_kill",
    "ptrace_access_check",
    "inode_unlink",
    "inode_rmdir",
    "inode_rename",
    "inode_setattr",
    "file_ioctl",
    "file_open",
    "inode_create",
    "inode_mkdir",
    "inode_mknod",
    "inode_symlink",
    "inode_link",
    "inode_setxattr",
    "inode_removexattr",
    "bpf_map",
    "inode_set_acl",
    "inode_remove_acl",
    "file_ioctl_compat",
    "bpf",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Slot order is wire-stable: the agent reads the map by slot. A new
    /// hook goes at the end; this pins every slot to its number and name.
    #[test]
    fn fail_open_slots_append_only() {
        let pinned: [(u32, &str); FAIL_OPEN_SLOTS as usize] = [
            (hook::TASK_KILL, "task_kill"),
            (hook::PTRACE_ACCESS_CHECK, "ptrace_access_check"),
            (hook::INODE_UNLINK, "inode_unlink"),
            (hook::INODE_RMDIR, "inode_rmdir"),
            (hook::INODE_RENAME, "inode_rename"),
            (hook::INODE_SETATTR, "inode_setattr"),
            (hook::FILE_IOCTL, "file_ioctl"),
            (hook::FILE_OPEN, "file_open"),
            (hook::INODE_CREATE, "inode_create"),
            (hook::INODE_MKDIR, "inode_mkdir"),
            (hook::INODE_MKNOD, "inode_mknod"),
            (hook::INODE_SYMLINK, "inode_symlink"),
            (hook::INODE_LINK, "inode_link"),
            (hook::INODE_SETXATTR, "inode_setxattr"),
            (hook::INODE_REMOVEXATTR, "inode_removexattr"),
            (hook::BPF_MAP, "bpf_map"),
            (hook::INODE_SET_ACL, "inode_set_acl"),
            (hook::INODE_REMOVE_ACL, "inode_remove_acl"),
            (hook::FILE_IOCTL_COMPAT, "file_ioctl_compat"),
            (hook::BPF, "bpf"),
        ];
        for (i, (slot, name)) in pinned.iter().enumerate() {
            assert_eq!(*slot as usize, i, "slot {name} moved");
            assert_eq!(FAIL_OPEN_HOOKS[i], *name);
        }
        assert_eq!(hook::BPF + 1, FAIL_OPEN_SLOTS);
    }
}
