//! Tappa 7 task 5 — userland half of filesystem protection.
//!
//! Bootstraps `/var/lib/northnarrow/`, marks it immutable, registers
//! its `(dev, ino)` in the kernel-side `PROTECTED_INODES` map, then
//! attaches the five `inode_*` / `file_ioctl` LSM programs that
//! enforce the policy.
//!
//! Order of operations matters:
//!
//! 1. **mkdir(0o700)** owned by root — same security envelope as
//!    `/etc/shadow`. We always run with `CAP_DAC_OVERRIDE` (the LSM
//!    attach already required root), so `uid:gid = root:root` is
//!    automatic on fresh creation.
//! 2. **`stat()` + insert into the BPF map** — done **before** the
//!    LSM hooks attach, so the very first kernel call into the hook
//!    already sees the protected key. Reverse order would leave a
//!    race window in which `rm -rf /var/lib/northnarrow` could
//!    succeed.
//! 3. **`chattr +i`** — defence in depth. The kernel's own
//!    immutability check rejects most modifications before our LSM
//!    hook even runs; the LSM hook then catches anyone who tries to
//!    `chattr -i` to drop the bit.
//! 4. **Attach the LSM programs** — last, on the already-populated
//!    map.

use std::fs::DirBuilder;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use aya::{
    maps::{HashMap as AyaHashMap, MapData},
    Btf, Ebpf,
};
use common::wire::InodeKey;

/// Aya requires its own marker trait [`aya::Pod`] for map K/V types,
/// distinct from `bytemuck::Pod`. The orphan rule prevents the
/// agent crate from implementing a foreign trait for the
/// `common::wire::InodeKey` foreign type, so we wrap it
/// transparently — same bytes, just an agent-local nominal type.
#[repr(transparent)]
#[derive(Copy, Clone)]
struct AyaInodeKey(InodeKey);

// SAFETY: `InodeKey` is `#[repr(C)]` over two `u64`s, has no
// padding gaps, and `AyaInodeKey` is `#[repr(transparent)]` over
// it. Every bit pattern is a valid `AyaInodeKey`.
unsafe impl aya::Pod for AyaInodeKey {}
use tracing::{info, warn};

/// State directory that the agent owns. Kept in sync with future
/// Tappa 8 paths that will live here (signed isolation state, audit
/// log). Hard-coded for now; promotable to config when Tappa 9 lands.
pub const STATE_DIR: &str = "/var/lib/northnarrow";

/// Permission bits applied at create time and re-asserted on every
/// startup (defends against an admin loosening perms while the
/// agent is offline).
const STATE_DIR_MODE: u32 = 0o700;

const PROTECTED_INODES_MAP: &str = "PROTECTED_INODES";

// `linux/fs.h` ioctl numbers for the `chattr` flag interface. Both
// values are stable Linux UABI on every architecture aya supports.
const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
const FS_IOC_SETFLAGS: libc::c_ulong = 0x4008_6602;
const FS_IMMUTABLE_FL: libc::c_long = 0x0000_0010;

/// The five LSM programs from `agent-ebpf/src/inode_protect.rs`.
/// First field is the program name in the ELF, second is the LSM
/// hook name the kernel exposes as `bpf_lsm_<hook>` in vmlinux BTF.
const LSM_PROGRAMS: &[(&str, &str)] = &[
    ("inode_unlink", "inode_unlink"),
    ("inode_rmdir", "inode_rmdir"),
    ("inode_rename", "inode_rename"),
    ("inode_setattr", "inode_setattr"),
    ("file_ioctl", "file_ioctl"),
];

pub(crate) fn attach(ebpf: &mut Ebpf, btf: &Btf) -> Result<()> {
    let dir = Path::new(STATE_DIR);

    // Step 1: ensure dir exists, mode 0700, root-owned.
    ensure_state_dir(dir).with_context(|| format!("preparing {}", dir.display()))?;
    let meta = std::fs::metadata(dir)
        .with_context(|| format!("re-stating {} after mkdir", dir.display()))?;
    info!(
        path = %dir.display(),
        mode = format!("{:o}", meta.mode() & 0o7777),
        uid = meta.uid(),
        gid = meta.gid(),
        "anti-tamper FS: state directory ready"
    );

    // Step 2: register inode in the BPF map BEFORE attaching hooks.
    let st_dev = meta.dev();
    let key = InodeKey {
        dev: stat_dev_to_kernel_dev(st_dev),
        ino: meta.ino(),
    };
    register_inode(ebpf, &key)?;
    info!(
        path = %dir.display(),
        st_dev = st_dev, kernel_dev = key.dev, ino = key.ino,
        "anti-tamper FS: directory inode registered in {PROTECTED_INODES_MAP}"
    );

    // Step 3: chattr +i (belt + suspenders; LSM is the primary).
    match chattr_immutable_add(dir) {
        Ok(true) => info!(path = %dir.display(), "anti-tamper FS: chattr +i applied"),
        Ok(false) => info!(path = %dir.display(), "anti-tamper FS: chattr +i already set"),
        Err(e) => warn!(
            error = %e, path = %dir.display(),
            "anti-tamper FS: chattr +i failed — LSM still protects, but the kernel \
             immutable check is unavailable"
        ),
    }

    // Step 4: attach the five LSM programs.
    for (program, hook) in LSM_PROGRAMS {
        match super::attach_lsm(ebpf, program, hook, btf) {
            Ok(()) => info!(program, hook, "anti-tamper FS: LSM hook attached"),
            Err(e) => warn!(
                program, hook, error = %e,
                "anti-tamper FS: LSM hook attach FAILED"
            ),
        }
    }

    Ok(())
}

fn ensure_state_dir(dir: &Path) -> Result<()> {
    // Try to create; tolerate AlreadyExists (idempotent startup).
    match DirBuilder::new()
        .mode(STATE_DIR_MODE)
        .recursive(true)
        .create(dir)
    {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(anyhow!(e).context(format!("mkdir {}", dir.display()))),
    }

    // Re-assert ownership + mode unconditionally so a slack umask
    // or a previous-version run with wider perms doesn't persist.
    let meta =
        std::fs::metadata(dir).with_context(|| format!("stat {} after mkdir", dir.display()))?;
    if !meta.is_dir() {
        return Err(anyhow!("{} exists and is not a directory", dir.display()));
    }

    if (meta.mode() & 0o7777) != STATE_DIR_MODE {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(STATE_DIR_MODE))
            .with_context(|| format!("chmod 0700 {}", dir.display()))?;
    }
    if meta.uid() != 0 || meta.gid() != 0 {
        // std::fs has no chown wrapper; reach for libc directly.
        let c_path = std::ffi::CString::new(dir.as_os_str().as_bytes())
            .with_context(|| format!("path {} contains NUL byte", dir.display()))?;
        // SAFETY: c_path is a valid NUL-terminated string; uid/gid
        // are the root constants; libc::chown only reads the path.
        let rc = unsafe { libc::chown(c_path.as_ptr(), 0, 0) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("chown root:root {}", dir.display()));
        }
    }
    Ok(())
}

/// Convert the userland-encoded `dev_t` returned by `stat(2)` /
/// `MetadataExt::dev()` back into the kernel-internal `MKDEV` form
/// that `inode->i_sb->s_dev` actually holds.
///
/// Why: the kernel stores `super_block.s_dev = MKDEV(major, minor) =
/// (major << 20) | minor`, but `stat(2)` runs that value through
/// `new_encode_dev()` before stamping it into `kstat.dev`, giving
/// `(minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12)`. For
/// `/dev/sda2` (major=8, minor=2) those are `0x800002` and `0x802`
/// respectively. The eBPF inode-protection hooks read the raw
/// `s_dev` directly, so the BPF map key MUST be in the kernel form.
/// See docs/TAPPA7_TASK5_DEEP_DEBUG.md §7 for the full diagnosis.
fn stat_dev_to_kernel_dev(st_dev: u64) -> u64 {
    let major = libc::major(st_dev) as u64;
    let minor = libc::minor(st_dev) as u64;
    (major << 20) | minor
}

fn register_inode(ebpf: &mut Ebpf, key: &InodeKey) -> Result<()> {
    let map = ebpf
        .map_mut(PROTECTED_INODES_MAP)
        .ok_or_else(|| anyhow!("map {PROTECTED_INODES_MAP} missing from eBPF object"))?;
    let mut map: AyaHashMap<&mut MapData, AyaInodeKey, u8> = AyaHashMap::try_from(map)
        .with_context(|| format!("{PROTECTED_INODES_MAP} is not a HashMap<InodeKey, u8>"))?;
    map.insert(AyaInodeKey(*key), 1u8, 0).with_context(|| {
        format!(
            "inserting (dev={}, ino={}) into {PROTECTED_INODES_MAP}",
            key.dev, key.ino
        )
    })?;
    Ok(())
}

/// Add `FS_IMMUTABLE_FL` to the file's inode flags via `ioctl`. Pure
/// Rust — no shelling out to `chattr`. Returns `Ok(true)` if we
/// actually had to set the bit (informational), `Ok(false)` if it
/// was already there.
fn chattr_immutable_add(path: &Path) -> Result<bool> {
    // `O_NOFOLLOW` defends against a symlink swap pointing the path
    // at /etc/something. `O_PATH` would be even safer (no read perm
    // required) but the `FS_IOC_*FLAGS` ioctls reject O_PATH fds,
    // so we open RDONLY.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open {} for chattr", path.display()))?;
    let fd = file.as_raw_fd();

    let mut flags: libc::c_long = 0;
    // SAFETY: `flags` is a valid `c_long` lvalue; the kernel writes
    // exactly `sizeof(long)` bytes into it on success. fd is owned.
    let rc = unsafe { libc::ioctl(fd, FS_IOC_GETFLAGS, &mut flags) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("FS_IOC_GETFLAGS on {}", path.display()));
    }
    if flags & FS_IMMUTABLE_FL != 0 {
        return Ok(false);
    }
    flags |= FS_IMMUTABLE_FL;
    // SAFETY: same `flags` pointer, this time read by the kernel.
    let rc = unsafe { libc::ioctl(fd, FS_IOC_SETFLAGS, &flags) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("FS_IOC_SETFLAGS on {}", path.display()));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_dev_to_kernel_dev_sda2() {
        // /dev/sda2 → major=8, minor=2.
        // stat(2) returns the new_encode_dev form 0x802.
        // Kernel-internal MKDEV form is (8 << 20) | 2 = 0x800002.
        assert_eq!(stat_dev_to_kernel_dev(0x802), 0x800002);
    }

    #[test]
    fn stat_dev_to_kernel_dev_high_minor() {
        // major=8, minor=257 (high-minor case so the encoded form's
        // ((minor & ~0xff) << 12) branch is non-zero).
        // new_encode_dev = (257 & 0xff) | (8 << 8) | ((257 & ~0xff) << 12)
        //                = 1 | 0x800 | (0x100 << 12)
        //                = 0x100801
        // MKDEV = (8 << 20) | 257 = 0x800101
        assert_eq!(stat_dev_to_kernel_dev(0x100801), 0x800101);
    }
}
