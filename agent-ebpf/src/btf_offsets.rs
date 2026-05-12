//! Hard-coded kernel struct field offsets.
//!
//! aya-ebpf 0.1 does not emit CO-RE field relocations from Rust
//! struct definitions, so every kernel pointer dereference in the
//! Tappa 7 LSM hooks goes through one of these byte offsets plus
//! `bpf_probe_read_kernel`. The constants here are captured from
//! `/sys/kernel/btf/vmlinux` on Ubuntu 24.04.4 / Linux
//! 6.8.0-111-generic (2026-05-12); the userland anti-tamper loader
//! revalidates each one against the running kernel's BTF before
//! attaching the hooks (the validation is being added alongside
//! Tappa 7 task 4 follow-ups).
//!
//! Drift is the failure mode to fear: a kernel upgrade can shift any
//! of these. The validation step is therefore the actual safety
//! contract — these constants are only the fast-path values.

/// `struct task_struct.tgid` — thread-group id, the value
/// `getpid(2)` returns to userland. `bits_offset=19936` from BTF.
pub(crate) const TASK_STRUCT_TGID_OFFSET: usize = 2492;

/// `struct dentry.d_inode` — the `*inode` pointer. `bits_offset=384`.
pub(crate) const DENTRY_D_INODE_OFFSET: usize = 48;

/// `struct inode.i_sb` — pointer to `super_block`. `bits_offset=448`.
pub(crate) const INODE_I_SB_OFFSET: usize = 56;

/// `struct inode.i_ino` — `unsigned long` (u64) inode number.
/// `bits_offset=640`.
pub(crate) const INODE_I_INO_OFFSET: usize = 80;

/// `struct super_block.s_dev` — `dev_t` (u32, packed major/minor).
/// `bits_offset=128`.
pub(crate) const SUPER_BLOCK_S_DEV_OFFSET: usize = 16;

/// `struct file.f_inode` — pointer to the file's inode.
/// `bits_offset=1344`.
pub(crate) const FILE_F_INODE_OFFSET: usize = 168;
