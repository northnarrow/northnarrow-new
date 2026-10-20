//! Tappa 7 task 5 — userland half of filesystem protection.
//!
//! Bootstraps `/var/lib/northnarrow/`, marks it immutable, registers
//! its `(dev, ino)` in the kernel-side `PROTECTED_INODES` map, then
//! attaches the `inode_*` / `file_ioctl` / `file_open` LSM deny programs
//! that enforce the policy ([`LSM_PROGRAMS`]).
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
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use aya::{
    maps::{HashMap as AyaHashMap, Map as AyaMap, MapData},
    Btf, Ebpf,
};
use common::wire::{
    InodeKey, FS_PROTECT_MUTATE, FS_PROTECT_NOCREATE, FS_PROTECT_READ, FS_PROTECT_WRITE,
    READ_PROTECTED_SLOTS,
};

/// Aya requires its own marker trait [`aya::Pod`] for map K/V types,
/// distinct from `bytemuck::Pod`. The orphan rule prevents the
/// agent crate from implementing a foreign trait for the
/// `common::wire::InodeKey` foreign type, so we wrap it
/// transparently — same bytes, just an agent-local nominal type.
#[repr(transparent)]
#[derive(Copy, Clone)]
pub(crate) struct AyaInodeKey(pub(crate) InodeKey);

// SAFETY: `InodeKey` is `#[repr(C)]` over two `u64`s, has no
// padding gaps, and `AyaInodeKey` is `#[repr(transparent)]` over
// it. Every bit pattern is a valid `AyaInodeKey`.
unsafe impl aya::Pod for AyaInodeKey {}
use tracing::{debug, error, info, warn};

/// State directory that the agent owns. Kept in sync with future
/// Tappa 8 paths that will live here (signed isolation state, audit
/// log). Hard-coded for now; promotable to config when Tappa 9 lands.
pub const STATE_DIR: &str = "/var/lib/northnarrow";

/// Config directory holding admin-controlled secrets + agent
/// identity files. Tappa 8 A14 (B4) widens PROTECTED_INODES to
/// cover this directory's contents so an attacker with root
/// can't tamper with `admin.pub` / `agent_id` / `audit.log` /
/// `agent.sig.key` between agent restarts. The directory itself is
/// registered too ([`PROTECTED_DIR_FLAGS`], review `etc-dir-protect-1`,
/// external audit EBPF-015): the agent writes it, operators change it
/// through the agent (`rotate-keys`, `config overlay set`) or inside a
/// trusted-installer window (install.sh).
pub const CONFIG_DIR: &str = "/etc/northnarrow";

/// External audit EBPF-015: the flags of the agent's own directories —
/// `/etc/northnarrow`, `/var/lib/northnarrow` and its chain
/// sub-directories, the unit drop-in directory ([`NOCREATE_UNIT_DIRS`]),
/// the bpffs pin root. MUTATE (no unlink, rename, chmod, chattr, xattr)
/// and NOCREATE: no new file, link, symlink, device node or subdirectory
/// in them from outside the agent's family, outside the window. Never on
/// a directory the agent shares with the host (`/usr/local/bin`,
/// `/etc/systemd/system`): only its own files are registered there.
pub(crate) const PROTECTED_DIR_FLAGS: u8 = FS_PROTECT_MUTATE | FS_PROTECT_NOCREATE;

/// The directories of [`BINARY_AND_UNIT_PATHS`] that take
/// [`PROTECTED_DIR_FLAGS`]: the agent unit's drop-in directory, which
/// install.sh creates on a Debian-family host. A new drop-in there could
/// replace `ExecStart=` or add a skipping `Condition*=` (DEP-002).
pub const NOCREATE_UNIT_DIRS: &[&str] = &["/etc/systemd/system/northnarrow-agent.service.d"];

/// The files inside [`CONFIG_DIR`] that PROTECTED_INODES covers.
/// Order is the operator-visible audit order — tests assert it for
/// stability.
///
/// - `admin.pub`: operator-provided. The W6 admin key allowlist.
/// - `agent_id`: agent-bootstrapped per design §6.5.
/// - `audit.log`: agent-appended per design §9 / commit B1.
/// - `agent.sig.key`: agent-bootstrapped per commit B1 (mode 0400).
/// - `fim-paths.v1` (Tappa 9 C7): the curated default watched-paths
///   list. Operator-readable, agent-readable; tamper here would
///   silently widen or narrow what the FIM module observes.
/// - `fim-paths.local` (Tappa 9 C7): the operator overlay (`+` add,
///   `-` disable). Same tamper concern; protected once the operator
///   places the file (the bootstrap WARN tolerates absence on
///   fresh installs).
/// - `netflow-blocklist.v1` (Tappa 10 N8): the curated default
///   IP / CIDR threat-intel blocklist consumed by NN-L-NET-001.
///   Tamper here would silently disable matches against known-bad
///   destinations (operator-curated baseline must not be erasable
///   by a foothold attacker).
/// - `netflow-blocklist.local` (Tappa 10 N8): operator overlay
///   for the IP / CIDR blocklist (`+entry` add, `-entry` disable).
///   Same tamper concern as `fim-paths.local`; protected once the
///   operator drops the file.
/// - `netflow-ja3-blocklist.v1` (Tappa 10 N8): the curated default
///   JA3 fingerprint threat-actor blocklist consumed by
///   NN-L-NET-003. Tamper would silently widen or narrow what
///   TLS handshakes match against the known-bad fingerprint set.
/// - `netflow-ja3-blocklist.local` (Tappa 10 N8): operator overlay
///   for the JA3 fingerprint blocklist. Same shape as the
///   IP blocklist `.local`.
///
/// Tappa 10 N8 APPENDS the four netflow blocklist files at the
/// END of the list — existing C7 + A14 positions stay stable so
/// any audit reader indexing by slot doesn't break across the
/// upgrade.
///
/// Tappa 10.5 D1 APPENDS the four comm-allowlist files
/// (`process-comm-allowlist.{v1,local}` +
/// `netflow-comm-allowlist.{v1,local}`) at the very END for the
/// same reason the C7 + N8 config files get protection: an attacker
/// who can edit an allowlist could silence detection by adding their
/// own tool's comm (or disabling a default) without ever touching a
/// rule. PROTECTED_INODES denies every non-agent caller, so the
/// allowlist files are as tamper-resistant as the blocklists. Append
/// keeps existing slots stable.
pub const ETC_PROTECTED_FILES: &[&str] = &[
    "admin.pub",
    "agent_id",
    "audit.log",
    "agent.sig.key",
    "fim-paths.v1",
    "fim-paths.local",
    "netflow-blocklist.v1",
    "netflow-blocklist.local",
    "netflow-ja3-blocklist.v1",
    "netflow-ja3-blocklist.local",
    "process-comm-allowlist.v1",
    "process-comm-allowlist.local",
    "netflow-comm-allowlist.v1",
    "netflow-comm-allowlist.local",
    // lab PR 21: written by install.sh, re-verified by the agent at boot
    "install-manifest.json",
    // Tappa 10.8: the posture overlays (were unprotected) and every
    // overlay's signature file. Overlays stay MUTATE-only on purpose: an
    // in-place edit cannot take effect without a new signature, and the
    // integrity check reports it.
    "mass-write-carveout.local",
    "escalation-allow.local",
    "fim-paths.local.sig",
    "netflow-blocklist.local.sig",
    "netflow-ja3-blocklist.local.sig",
    "process-comm-allowlist.local.sig",
    "netflow-comm-allowlist.local.sig",
    "mass-write-carveout.local.sig",
    "escalation-allow.local.sig",
    // External audit ATP-001 / DEP-003: the files COMBAT isolates with and
    // their signatures. MUTATE-only like the other operator-tunable files;
    // the signature check at every engage is what vouches for the content.
    "combat-rules.v4",
    "combat-rules.v6",
    "combat-allow.cidrs",
    "combat-rules.v4.sig",
    "combat-rules.v6.sig",
    "combat-allow.cidrs.sig",
    // External audit DEC-005: the readers a File / Credential canary
    // spares, and their signature. MUTATE-only like the other overlays.
    "canary-readers.local",
    "canary-readers.local.sig",
    // External audit EVD-001: the signing key's public half, written by
    // the agent; what `nn-admin audit verify` reads.
    "agent.sig.pub",
    // External audit NN-AUD-108 (lab PR 160): the signed head anchor of the
    // chains (`crate::chain_anchor`), next to the audit log it anchors.
    "chain_heads.json",
];

/// External audit EVD-001: the subset of [`ETC_WRITE_DENY_FILES`] no
/// process outside the agent's family may open at all, to read included
/// (`FS_PROTECT_READ`): the private signing key. Root read it and could
/// rebuild every signed chain offline. Its public half is
/// `agent.sig.pub`. At most [`READ_PROTECTED_SLOTS`] entries.
pub const ETC_READ_DENY_FILES: &[&str] = &["agent.sig.key"];

/// at-authz-1: the subset of [`ETC_PROTECTED_FILES`] that is also
/// WRITE-open-denied (`FS_PROTECT_WRITE`), not just mutation-denied.
/// These are the secret/integrity identity files written ONLY by the
/// agent at runtime (admin.pub via the rename-based rotate-keys path;
/// agent_id / agent.sig.key at bootstrap; audit.log via the append-only
/// chain), so any runtime non-agent write is unambiguous tamper; so are
/// the shipped `.v1` lists, which only install.sh writes. The `.local`
/// overlays operators tune stay MUTATE-only and are signature-gated.
/// Every entry MUST also appear in [`ETC_PROTECTED_FILES`].
pub const ETC_WRITE_DENY_FILES: &[&str] = &[
    "admin.pub",
    "agent_id",
    "audit.log",
    "agent.sig.key",
    // External audit EVD-001: the public half, written by the agent at
    // start; what `nn-admin audit verify` reads.
    "agent.sig.pub",
    // Lab PR 160: the head anchor, written only by the agent.
    "chain_heads.json",
    // written only by install.sh with the units stopped; an append at
    // runtime corrupts the boot-time integrity check (observed on the
    // lab guest: `echo x >>` went through while MUTATE-only).
    "install-manifest.json",
    // External audit FIMR-001: the shipped FIM path list, written only by
    // install.sh (operators tune `fim-paths.local`, which stays
    // MUTATE-only and is signature-gated). An append at runtime could
    // add lines the next boot reads.
    "fim-paths.v1",
    // External audit ATP-008: the other shipped lists, on the same
    // reasoning — install.sh writes them with the pins dropped, operators
    // tune the signed `.local` overlays (`nn-admin config overlay set`).
    // An in-place append blinded a blocklist or allowlisted a comm at the
    // next boot, with nothing refused.
    "netflow-blocklist.v1",
    "netflow-ja3-blocklist.v1",
    "process-comm-allowlist.v1",
    "netflow-comm-allowlist.v1",
];

/// Tappa 9 C7 + Tappa 9.5 K7: the files inside [`STATE_DIR`] that
/// PROTECTED_INODES covers. The directory itself is already
/// registered (Tappa 7 task 5); these per-file registrations
/// cover the case where an attacker can `creat`/`unlink` inside
/// the dir but not the dir itself — `inode_unlink` checks the
/// TARGET inode, not the parent.
///
/// - `fim_baseline.jsonl`: chained baseline DB per §6.2. Agent
///   appends via `BaselineDb::append`; everyone else must be denied
///   so an attacker can't truncate the chain to hide pre-incident
///   baselines.
/// - `fim_drift.jsonl`: chained drift log per §6.3. Same shape;
///   tampering would let an attacker erase evidence of past
///   drift detections.
/// - `canaries.jsonl` (Tappa 9.5 K7): chained canary registry
///   per Tappa 9.5 §3.4. Agent appends via `Registry::deploy` /
///   `burn` / `refresh`; tampering would let an attacker drop a
///   `burn` row to fake-retire a canary that's still trapping
///   them, OR delete the chain to erase the operator's complete
///   deployment history.
/// - `canary_access.jsonl` (Tappa 9.5 K7): chained canary
///   access log per Tappa 9.5 §3.5. One row per observed trip;
///   tampering would erase the audit-grade incident record an
///   operator hands to IR.
/// - `netflow.jsonl` (Tappa 10 N8): chained NetFlow event log
///   per design §6.4 + §4.4. Agent appends one row per closed
///   flow (the §6.5 rate limiter never suppresses the on-disk
///   row, only the decision-engine emission); tampering would
///   let an attacker erase the audit-grade flow record an
///   operator hands to IR — same lock-in as the FIM + canary
///   chains.
/// - `netflow_listeners.jsonl` (Tappa 10 N9): chained NetListener
///   event log per design §6.4. Same protection rationale as
///   `netflow.jsonl` — the on-disk row is the IR-grade record
///   that an attacker would otherwise truncate to hide a
///   pre-existing reverse-shell listener.
///
/// Tappa 9.5 K7 APPENDS the two canary chains at the END of the
/// list; Tappa 10 N8 then APPENDS `netflow.jsonl` after the
/// canary chains; Tappa 10 N9 APPENDS `netflow_listeners.jsonl`
/// at the very end. Existing entries' positions stay stable so
/// any audit reader indexing by slot doesn't break across the
/// upgrade.
pub const STATE_PROTECTED_FILES: &[&str] = &[
    "fim_baseline.jsonl",
    "fim_drift.jsonl",
    "canaries.jsonl",
    "canary_access.jsonl",
    "netflow.jsonl",
    "netflow_listeners.jsonl",
];

/// Audit `chain-protect-1` / `at-authz-3`: chain logs that live in a
/// SUB-directory of the state dir. `(subdir basename, file basenames)`;
/// both halves are bare basenames (same path-traversal invariant as
/// [`STATE_PROTECTED_FILES`]). The subdir inode itself is registered
/// MUTATE (no rmdir/rename/chattr of the dir, no rename into or out of
/// it), the files MUTATE|WRITE like every other chain log. Before this,
/// `register_state_files` only did `state_dir.join(<basename>)` and the
/// Tappa 9.0 detection chains — `detections.jsonl` and the triage
/// `status_events.jsonl` — were deletable/truncatable by root with no
/// denial (signed, so detectable after the fact, but not defended).
pub const STATE_PROTECTED_SUBDIRS: &[(&str, &[&str])] =
    &[("detections", &["detections.jsonl", "status_events.jsonl"])];

/// Tappa 9.5 K7: subdirectory under [`CONFIG_DIR`] holding the
/// K4 canary content templates the renderer reads at
/// `canary deploy` time. The directory itself is created by
/// `install.sh`; the individual `.tmpl` files are listed in
/// [`ETC_PROTECTED_TEMPLATES`] so PROTECTED_INODES covers each.
pub const CANARY_TEMPLATES_SUBDIR: &str = "canary-templates";

/// Tappa 9.5 K7: the five `.tmpl` files inside
/// `/etc/northnarrow/canary-templates/` that PROTECTED_INODES
/// covers. Tamper here would silently widen / narrow what bytes
/// get written onto the host at `canary deploy` time — a
/// realistic attack path against an operator who's deployed
/// credential canaries (the renderer's output IS the on-disk
/// canary content the attacker sees).
///
/// Order is alphabetical for audit-log stability, matching the
/// same convention as [`ETC_PROTECTED_FILES`] +
/// [`STATE_PROTECTED_FILES`]. Each entry is a BARE BASENAME so
/// the same path-traversal invariant holds (asserted by
/// `etc_protected_files_have_no_path_traversal` shape tests).
pub const ETC_PROTECTED_TEMPLATES: &[&str] = &[
    "aws.tmpl",
    "azure.tmpl",
    "docker.tmpl",
    "gcp.tmpl",
    "generic.tmpl",
];

/// Anti-tamper binary/unit pin: the agent + watchdog executables and
/// their systemd unit files. Registered in `PROTECTED_INODES` (Step
/// 3.8 of [`attach`]) so the same five `inode_*` / `file_ioctl` LSM
/// modification-deny hooks that defend the [`ETC_PROTECTED_FILES`]
/// identity files also defend the agent's own on-disk image and
/// service definitions. Without this a root attacker could `cp` over
/// `/usr/local/bin/northnarrow-agent` (the truncate routes through
/// `inode_setattr`) or rename a tampered unit into place
/// (`inode_rename`) and neutralise the agent while `systemctl` still
/// reports it "running".
///
/// Unlike the other protected-path consts (bare basenames under one
/// directory), these are ABSOLUTE paths — the set spans the binary and
/// unit directories, so there is no single parent dir to join. The
/// `.service` files are the same units the FIM-009 trusted-installer
/// override governs ([`super::trusted_installer::OWN_SYSTEMD_UNITS`]).
///
/// Review 26: both install layouts are listed. `install.sh` puts the
/// binaries in `/usr/local/bin` and the units in `/etc/systemd/system`;
/// a distro package puts them in `/usr/bin` and the vendor unit
/// directory `/usr/lib/systemd/system`. Registration skips the paths
/// that do not exist, so each host protects the layout it has (both,
/// during a migration from one to the other).
///
/// eBPF-only, NO `chattr +i`: the `+i` belt-and-suspenders stays the
/// state dir's. These use the file-LSM mechanism for consistency with
/// the /etc identity files — and so a signed self-upgrade can replace
/// them during an armed trusted-installer window (`FS_GRANT`) (a global deny
/// suspension) without first having to clear a per-inode immutable
/// bit.
pub const BINARY_AND_UNIT_PATHS: &[&str] = &[
    "/usr/local/bin/northnarrow-agent",
    "/usr/local/bin/northnarrow-watchdog",
    "/etc/systemd/system/northnarrow-agent.service",
    "/etc/systemd/system/northnarrow-watchdog.service",
    "/usr/bin/northnarrow-agent",
    "/usr/bin/northnarrow-watchdog",
    "/usr/lib/systemd/system/northnarrow-agent.service",
    "/usr/lib/systemd/system/northnarrow-watchdog.service",
    // External audit DEP-002: the drop-in install.sh writes on a Debian
    // host (a drop-in can replace ExecStart=, add a Condition*= that skips
    // the start, or set a weakening Environment=), and its directory —
    // removing or renaming an entry is denied, and since EBPF-015 a new
    // drop-in too (`NOCREATE_UNIT_DIRS`). Where the directory does not
    // exist, a drop-in made with it is reported by the integrity check.
    "/etc/systemd/system/northnarrow-agent.service.d",
    "/etc/systemd/system/northnarrow-agent.service.d/10-debian-perf-paranoid.conf",
];

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

/// The LSM deny programs from `agent-ebpf/src/inode_protect.rs` every
/// supported kernel (5.14+) has a hook for. First field is the program
/// name in the ELF, second is the LSM hook name the kernel exposes as
/// `bpf_lsm_<hook>` in vmlinux BTF. `protected_open_deny` (at-authz-1) is
/// the `file_open` FMODE_WRITE deny that closes the write-open gap on
/// `FS_PROTECT_WRITE` inodes. External audit EBPF-015 appends the
/// new-entry denies (NOCREATE directories) and the extended-attribute
/// denies.
pub(crate) const LSM_PROGRAMS: &[(&str, &str)] = &[
    ("inode_unlink", "inode_unlink"),
    ("inode_rmdir", "inode_rmdir"),
    ("inode_rename", "inode_rename"),
    ("inode_setattr", "inode_setattr"),
    ("file_ioctl", "file_ioctl"),
    ("protected_open_deny", "file_open"),
    ("protected_create_deny", "inode_create"),
    ("protected_mkdir_deny", "inode_mkdir"),
    ("protected_mknod_deny", "inode_mknod"),
    ("protected_symlink_deny", "inode_symlink"),
    ("protected_link_deny", "inode_link"),
    ("protected_setxattr_deny", "inode_setxattr"),
    ("protected_removexattr_deny", "inode_removexattr"),
];

/// External audit EBPF-015: deny programs for hooks only newer kernels
/// have. Since 6.2 a POSIX ACL (`setfacl`) is changed through
/// `inode_set_acl` / `inode_remove_acl` instead of `inode_setxattr`
/// (`system.posix_acl_*`), which the required set covers on 5.15 and 6.1.
/// Lab PR 174: since 6.8 (and the stable releases 6.7.3, 6.6.15, 6.1.76,
/// 5.15.149, 5.10.210) a 32-bit process's `ioctl` goes through
/// `file_ioctl_compat` instead of `file_ioctl`, which covers it on older
/// kernels. Attached where the kernel's BTF has the hook
/// (`bpf_lsm_<hook>`); where it has not, the program is skipped and not
/// counted as a missing deny hook. A hook the kernel has but that fails to
/// load or attach is a deny failure like any other.
pub(crate) const OPTIONAL_LSM_PROGRAMS: &[(&str, &str)] = &[
    ("protected_set_acl_deny", "inode_set_acl"),
    ("protected_remove_acl_deny", "inode_remove_acl"),
    ("protected_ioctl_compat_deny", "file_ioctl_compat"),
];

/// BUG-034 module-load observe hooks — `MODULE_LOAD_EVENTS` producers.
/// Observe-only (return 0); the rootkit verdict is userland's (stage 2
/// rule). Attached via the same `reattach_fresh` discipline as the
/// `LSM_PROGRAMS` deny set (zero-window + no ring split-brain across
/// restart). (program-name, hook-name); both share the source file
/// `agent-ebpf/src/module_load.rs`.
///
/// NOTE: temporarily attached here to reuse the `reattach_fresh`
/// machinery with `btf` + `pin_root` in scope; moves to a dedicated
/// module-load sensor when the ring consumer + rule land in stage 2.
const MODULE_LOAD_PROGRAMS: &[(&str, &str)] = &[
    ("module_read_file_observe", "kernel_read_file"),
    ("module_load_data_observe", "kernel_load_data"),
];

/// Attach outcome of the FS deny + observe hook sets (audit
/// `ebpf-lsm-1`): the caller aggregates it with task_kill/ptrace into one
/// machine-readable health line and decides fail-closed vs degraded.
#[derive(Debug, Default)]
pub(crate) struct FsAttachHealth {
    /// `(program, error)` for every inode_protect DENY hook that did not
    /// attach. Non-empty = mutation / write-open protection partially OFF.
    pub deny_failures: Vec<(&'static str, String)>,
    /// Same for the module-load OBSERVE hooks (BUG-034). Non-empty =
    /// R018 blind, but no deny is missing.
    pub observe_failures: Vec<(&'static str, String)>,
    /// External audit EBPF-015: the [`OPTIONAL_LSM_PROGRAMS`] whose hook
    /// this kernel has — attached or failed, they count as expected deny
    /// hooks.
    pub optional_present: usize,
    /// External audit ATP-007 / ATP-016: protection steps that are not
    /// hooks and failed — an agent directory found to be a symbolic link,
    /// left unregistered; the bootstrap error itself. They refuse the start
    /// without lowering the hook count.
    pub infra_failures: Vec<(&'static str, String)>,
}

/// External audit ATP-016 (NN-AUD-264): the health of an FS bootstrap that
/// failed before any hook — every deny program of [`LSM_PROGRAMS`], each
/// of [`OPTIONAL_LSM_PROGRAMS`] whose hook this kernel has, the module-load
/// observers — with the error as a failed step. `in_kernel` is the boot's
/// BTF resolution ([`super::btf_revalidate::optional_hook_in_kernel`]); an
/// optional hook whose presence is unknown is not counted (the attach
/// finds that out by trying, and nothing was tried).
pub(crate) fn hooks_lost_to_bootstrap_failure(
    in_kernel: impl Fn(&str) -> Option<bool>,
    why: String,
) -> FsAttachHealth {
    let lost = "not attached: the FS protection bootstrap failed".to_string();
    let mut health = FsAttachHealth::default();
    for (program, _) in LSM_PROGRAMS {
        health.deny_failures.push((program, lost.clone()));
    }
    for (program, hook) in OPTIONAL_LSM_PROGRAMS {
        if in_kernel(hook) == Some(true) {
            health.optional_present += 1;
            health.deny_failures.push((program, lost.clone()));
        }
    }
    for (program, _) in MODULE_LOAD_PROGRAMS {
        health.observe_failures.push((program, lost.clone()));
    }
    health.infra_failures.push(("filesystem::attach", why));
    health
}

/// External audit ATP-007 (NN-AUD-260): the agent's directories outside
/// the state directory that take [`PROTECTED_DIR_FLAGS`]: `/etc/northnarrow`
/// and the unit drop-in directory. One found to be a symbolic link is not
/// registered — its target is not known to be the agent's — and the start
/// is refused (a failed step).
fn linked_agent_dirs() -> Vec<String> {
    std::iter::once(CONFIG_DIR)
        .chain(NOCREATE_UNIT_DIRS.iter().copied())
        .filter_map(|d| link_at(Path::new(d)))
        .collect()
}

pub(crate) fn attach(
    ebpf: &mut Ebpf,
    btf: &Btf,
    pin_root: Option<&Path>,
) -> Result<FsAttachHealth> {
    let mut health = FsAttachHealth::default();
    let dir = Path::new(STATE_DIR);

    // Step 1: ensure dir exists, mode 0700, root-owned — the directory
    // itself, never a link's target (external audit ATP-007): `meta` is the
    // repaired descriptor's, and its key is what Step 2 registers.
    let meta = ensure_state_dir(dir).with_context(|| format!("preparing {}", dir.display()))?;
    // Step 1.5: the response executor's vault, before the dir is `+i`.
    if let Err(e) = ensure_quarantine_dirs(dir) {
        warn!(
            error = format!("{e:#}"),
            "anti-tamper FS: quarantine vault directory not created — a quarantine will fail"
        );
    }
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
    // The state dir is a directory — a write-open (FMODE_WRITE) of a dir
    // never happens (open returns EISDIR), so no WRITE bit; the WRITE bit
    // lives on the chain-log FILES inside it (register_state_files).
    // NOCREATE (EBPF-015): `+i` kept new entries out only while root could
    // not clear it, and the agent lifts it for its own creates.
    register_inode(ebpf, &key, PROTECTED_DIR_FLAGS)?;
    crate::fs_type::note_identity(dir);
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

    // External audit ATP-007: the other NOCREATE directories are never
    // registered through a link (`register_etc_files`, `resolve_protected_paths`
    // skip it); one that is a link refuses the start.
    for link in linked_agent_dirs() {
        error!(
            link = %link,
            "anti-tamper FS: one of the agent's directories is a symbolic link — not followed, \
             its directory protection is NOT applied"
        );
        health.infra_failures.push((
            "linked agent directory",
            format!(
                "{link}: not followed, the directory is not protected (put the real directory \
                 back, or bind-mount one there)"
            ),
        ));
    }

    // Step 3.5 (Tappa 8 A14 / B4): register the six
    // /etc/northnarrow/ files in PROTECTED_INODES so the LSM
    // hooks defend them too. Lenient: files that don't exist
    // yet (audit.log on first install before any admin op, or
    // agent.sig.key on a pre-B1 deploy, or fim-paths.local on a
    // deploy with no operator overlay) are skipped with a warn.
    // The caller-side PROTECTED_PIDS exemption in the BPF
    // program (also A14) keeps the agent's own A13 rotate-keys
    // atomic rewrite from being self-denied.
    if let Err(e) = register_etc_files(ebpf, Path::new(CONFIG_DIR)) {
        warn!(
            error = %e,
            "anti-tamper FS: /etc/northnarrow file registration failed — \
             config files defended only by POSIX perms this boot"
        );
    }

    // Step 3.6 (Tappa 9 C7 + Tappa 9.5 K7): register the four
    // /var/lib/northnarrow/ chain logs in PROTECTED_INODES. The
    // parent dir is already protected (Step 2 above), but
    // inode_unlink + inode_setattr check the TARGET inode, so
    // a file inside the dir is unprotected without an explicit
    // per-file registration. Lenient like Step 3.5: a fresh
    // install that hasn't yet run its first baseline (no
    // fim_baseline.jsonl yet) OR hasn't deployed any canary
    // yet (no canaries.jsonl) skips with a warn. The
    // PROTECTED_PIDS caller-side exemption lets the agent
    // append legitimately.
    if let Err(e) = register_state_files(ebpf, Path::new(STATE_DIR)) {
        warn!(
            error = %e,
            "anti-tamper FS: /var/lib/northnarrow chain-log registration failed — \
             baseline + drift + canary logs defended only by POSIX perms + dir-LSM this boot"
        );
    }

    // Step 3.7 (Tappa 9.5 K7): register the five canary content
    // templates in /etc/northnarrow/canary-templates/ in
    // PROTECTED_INODES. Tamper here would silently widen /
    // narrow what bytes get written onto the host at
    // `canary deploy` time — a realistic attack path against
    // an operator who's deployed credential canaries (the
    // renderer's output IS the on-disk canary content the
    // attacker sees). Lenient: a fresh install before
    // install.sh has dropped the templates skips with a warn.
    if let Err(e) = register_etc_templates(ebpf, Path::new(CONFIG_DIR)) {
        warn!(
            error = %e,
            "anti-tamper FS: canary template registration failed — \
             /etc/northnarrow/canary-templates/ defended only by POSIX perms this boot"
        );
    }

    // Step 3.8 (anti-tamper binary/unit pin): register the agent +
    // watchdog BINARIES and their systemd UNIT files in
    // PROTECTED_INODES so the same five LSM modification-deny hooks
    // that defend the /etc identity files also defend the agent's own
    // executable + service files. Registered BEFORE the hooks attach
    // (Step 4) so the kernel never sees an unprotected window — same
    // ordering as the /etc + state + template registrations above.
    // Lenient like Step 3.5–3.7: a host without the watchdog binary
    // (or a package layout that omits a unit) skips that path with a
    // warn rather than aborting arming. The caller-side PROTECTED_PIDS
    // exemption already lets the agent re-exec itself and the watchdog
    // re-install; a signed installer replaces these during an armed
    // trusted-installer window (FS_GRANT).
    if let Err(e) = register_binary_and_units(ebpf) {
        warn!(
            error = %e,
            "anti-tamper FS: agent binary/unit registration failed — \
             agent executable + service files defended only by POSIX perms this boot"
        );
    }

    // Step 4: attach the inode_protect deny hooks — the
    // FS_PROTECT_EVENTS producers. BUG-024: these MUST re-attach FRESH
    // every boot (binding to this boot's fresh, process-local ring) rather
    // than reuse the prior boot's pinned link (which kept producing into the
    // old pinned ring and desynced the new consumer → ~1.6k/sec stale-denial
    // replay that DoS'd observability). `reattach_fresh` attaches this boot's
    // program BEFORE purging the old pin, so a deny program is attached at
    // every instant (zero-window). task_kill/ptrace (anti_tamper/mod.rs) emit
    // on the same ring and are reattached fresh too (review 62).
    let mut deny_hooks_attached: usize = 0;
    for (program, hook) in LSM_PROGRAMS {
        // Lab PR 164: the setattr and xattr denies read the dentry at the
        // position the running kernel's prototype gives (setattr: 1 from
        // 6.9, 0 before; xattr: 0 on 5.7-5.11, 1 after). Unknown position:
        // not attached, a deny shortfall like a verifier reject, and the
        // prior boot's pins of this hook go too, so that no older program
        // keeps reading a fixed position.
        if let Some(Err(why)) = super::btf_revalidate::hook_attach_gate(hook) {
            warn!(
                program, hook, reason = %why,
                effect = super::btf_revalidate::hook_arg_effect(&format!("bpf_lsm_{hook}")),
                "anti-tamper FS: deny hook NOT attached — the dentry's position in the hook's \
                 prototype is unknown"
            );
            if let Some(root) = pin_root {
                let (prog_pin, link_pin) = antitamper_bpf::lsm_pin_paths(root, hook);
                antitamper_bpf::purge_stale_pin(&link_pin);
                antitamper_bpf::purge_stale_pin(&prog_pin);
            }
            health.deny_failures.push((program, why));
            continue;
        }
        match super::reattach_fresh(ebpf, program, hook, btf, pin_root) {
            Ok(()) => deny_hooks_attached += 1,
            Err(e) => {
                warn!(
                    program, hook, error = %e,
                    "anti-tamper FS: LSM hook attach FAILED"
                );
                health.deny_failures.push((program, format!("{e:#}")));
            }
        }
    }
    // External audit EBPF-015: the hooks only newer kernels have. Absent
    // from this kernel's BTF = not expected here (the required set covers
    // the same change on it); present = expected, like the required ones.
    // Lab PR 174: the boot's BTF resolution says whether the kernel has
    // `bpf_lsm_<hook>` (`attach_optional`).
    for (program, hook) in OPTIONAL_LSM_PROGRAMS {
        let in_btf = super::btf_revalidate::optional_hook_in_kernel(hook);
        let outcome = attach_optional(hook, in_btf, || {
            super::reattach_fresh(ebpf, program, hook, btf, pin_root)
        });
        if outcome.expected() {
            health.optional_present += 1;
        }
        match outcome {
            OptionalHook::Absent => info!(
                program,
                hook, "anti-tamper FS: optional deny hook absent on this kernel — not attached"
            ),
            OptionalHook::Attached => deny_hooks_attached += 1,
            OptionalHook::Failed(e) => {
                warn!(
                    program, hook, error = %e,
                    "anti-tamper FS: LSM hook attach FAILED"
                );
                health.deny_failures.push((program, e));
            }
        }
    }
    // at-authz-1 verify-item 3: a machine-detectable attach-health signal
    // (attached vs expected). The fail-closed decision itself is the
    // caller's (anti_tamper::attach, audit ebpf-lsm-1) — it sees this
    // set together with task_kill / ptrace.
    let deny_hooks_expected = LSM_PROGRAMS.len() + health.optional_present;
    if deny_hooks_attached == deny_hooks_expected {
        info!(
            deny_hooks_attached,
            deny_hooks_expected, "anti-tamper FS: all inode_protect deny hooks attached"
        );
    } else {
        warn!(
            deny_hooks_attached,
            deny_hooks_expected,
            "anti-tamper FS: DENY HOOK SHORTFALL — write-open/mutation protection \
             partially absent (monitor: deny_hooks_attached < deny_hooks_expected)"
        );
    }

    // Step 5 (BUG-034): attach the two module-load OBSERVE hooks —
    // MODULE_LOAD_EVENTS producers — on the same reattach-fresh path as
    // the deny set above (zero-window + no ring split-brain on restart).
    // Observe-only; the rootkit verdict is userland's (stage-2 rule).
    for (program, hook) in MODULE_LOAD_PROGRAMS {
        if let Err(e) = super::reattach_fresh(ebpf, program, hook, btf, pin_root) {
            warn!(
                program, hook, error = %e,
                "anti-tamper FS: module-load LSM hook attach FAILED (BUG-034)"
            );
            health.observe_failures.push((program, format!("{e:#}")));
        }
    }

    Ok(health)
}

/// How an optional deny hook ([`OPTIONAL_LSM_PROGRAMS`]) counts this boot.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum OptionalHook {
    /// The kernel has no such hook: not attached, not expected.
    Absent,
    /// Attached: one more expected deny hook, present.
    Attached,
    /// The kernel has the hook but its program did not load or attach: an
    /// expected deny hook missing (a shortfall, like a required one).
    Failed(String),
}

impl OptionalHook {
    /// Whether the hook counts among this boot's expected deny hooks.
    pub(crate) fn expected(&self) -> bool {
        !matches!(self, OptionalHook::Absent)
    }
}

/// Lab PR 174: attach the optional deny hook `hook` only where the
/// kernel's BTF has it. `in_btf` is the boot's BTF resolution
/// ([`super::btf_revalidate::optional_hook_in_kernel`]): `Some(false)`
/// skips the hook without trying; `Some(true)` makes any attach error a
/// failure; `None` (no resolution) leaves the decision to the loader's own
/// lookup, whose "no `bpf_lsm_<hook>`" error ([`lsm_hook_absent`]) means
/// absent.
pub(crate) fn attach_optional(
    hook: &str,
    in_btf: Option<bool>,
    attach: impl FnOnce() -> Result<()>,
) -> OptionalHook {
    if in_btf == Some(false) {
        return OptionalHook::Absent;
    }
    match attach() {
        Ok(()) => OptionalHook::Attached,
        Err(e) if in_btf.is_none() && lsm_hook_absent(&e, hook) => OptionalHook::Absent,
        Err(e) => OptionalHook::Failed(format!("{e:#}")),
    }
}

/// External audit EBPF-015: whether `err`, from attaching the deny
/// program for `hook`, says the kernel has no such LSM hook
/// (`bpf_lsm_<hook>` absent from its BTF) — as opposed to a hook it has
/// failing to load or attach.
pub(crate) fn lsm_hook_absent(err: &anyhow::Error, hook: &str) -> bool {
    let want = format!("bpf_lsm_{hook}");
    err.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<aya::programs::ProgramError>(),
            Some(aya::programs::ProgramError::Btf(aya::BtfError::UnknownBtfTypeName { type_name }))
                if *type_name == want
        )
    })
}

/// External audit ATP-007 (NN-AUD-260): the metadata of the agent's own
/// entry at `path` (`lstat`), never of what a link there points to. A link
/// in one of the agent's directories was planted by a root: the link is
/// registered (its unlink and rename are refused like the file's), not its
/// target, which a registration by `stat` would have write-denied — a
/// `fim_baseline.jsonl -> /etc/passwd` made `/etc/passwd` unwritable.
fn own_entry_meta(path: &Path) -> std::io::Result<std::fs::Metadata> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        warn!(
            link = %link_at(path).unwrap_or_else(|| path.display().to_string()),
            "anti-tamper FS: a symbolic link where the agent keeps its own file — the link is \
             registered, not its target"
        );
    }
    Ok(meta)
}

/// Tappa 8 A14 (B4): register each of the four [`ETC_PROTECTED_FILES`]
/// in `PROTECTED_INODES` so the same LSM hooks that defend
/// `/var/lib/northnarrow` also defend admin.pub / agent_id /
/// audit.log / agent.sig.key. Missing files are skipped with a
/// warn (a fresh install before the first admin op has no
/// audit.log; a pre-B1 deploy has no agent.sig.key); present
/// files are registered before the LSM hooks attach so the
/// kernel never sees an unprotected window.
///
/// Returns the number of files actually registered, for the
/// info-log line.
pub(crate) fn register_etc_files(ebpf: &mut Ebpf, etc_dir: &Path) -> Result<usize> {
    let mut registered = 0usize;
    let mut read_protected: Vec<u64> = Vec::new();
    // Review `etc-dir-protect-1`: the DIRECTORY inode too. The files
    // below are mutation-denied, but the directory that holds them was
    // not, so `mv /etc/northnarrow /etc/x` (or rmdir after an unlink
    // sweep by a process not in PROTECTED_PIDS) relocated the whole
    // identity tree out from under the agent's hardcoded paths — the
    // next boot would bootstrap fresh keys. MUTATE on the directory
    // denies its unlink/rmdir/rename/setattr/chattr AND, through the
    // old_dir/new_dir checks in inode_rename, every rename into or out
    // of it by a non-protected pid. The agent's own rotate-keys rename
    // is exempt via PROTECTED_PIDS; operator edits go through the signed
    // trusted-installer window (FS_GRANT), exactly like /var/lib/northnarrow.
    // External audit EBPF-015: NOCREATE too — root could still add any
    // file next to the protected ones (a decoy overlay, a planted `.tmp`
    // name, a second key file).
    // External audit ATP-007: the directory itself (`lstat`); a link is not
    // registered (`attach` refuses the start for it).
    match std::fs::symlink_metadata(etc_dir) {
        Ok(meta) if meta.is_dir() => {
            let key = InodeKey {
                dev: stat_dev_to_kernel_dev(meta.dev()),
                ino: meta.ino(),
            };
            register_inode(ebpf, &key, PROTECTED_DIR_FLAGS).with_context(|| {
                format!(
                    "registering directory {} in {PROTECTED_INODES_MAP}",
                    etc_dir.display()
                )
            })?;
            crate::fs_type::note_identity(etc_dir);
            info!(
                path = %etc_dir.display(),
                kernel_dev = key.dev,
                ino = key.ino,
                "anti-tamper FS: /etc/northnarrow directory inode registered in {PROTECTED_INODES_MAP}"
            );
            registered += 1;
        }
        Ok(meta) if meta.file_type().is_symlink() => error!(
            link = %link_at(etc_dir).unwrap_or_default(),
            "anti-tamper FS: config dir is a symbolic link — not followed, directory inode not \
             registered"
        ),
        Ok(_) => warn!(
            path = %etc_dir.display(),
            "anti-tamper FS: config dir path is not a directory — not registered"
        ),
        Err(e) => warn!(
            error = %e,
            path = %etc_dir.display(),
            "anti-tamper FS: config dir missing — directory inode not registered"
        ),
    }
    for name in ETC_PROTECTED_FILES {
        let path = etc_dir.join(name);
        let meta = match own_entry_meta(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                warn!(
                    path = %path.display(),
                    "anti-tamper FS: skip register_etc_files entry — file missing \
                     (will be unprotected until next agent restart with the file present)"
                );
                continue;
            }
            Err(e) => {
                warn!(
                    error = %e,
                    path = %path.display(),
                    "anti-tamper FS: stat failed for register_etc_files entry"
                );
                continue;
            }
        };
        let key = InodeKey {
            dev: stat_dev_to_kernel_dev(meta.dev()),
            ino: meta.ino(),
        };
        // at-authz-1: secret/integrity identity files (ETC_WRITE_DENY_FILES)
        // get WRITE+MUTATE; operator-tunable files get MUTATE only.
        let read_deny = ETC_READ_DENY_FILES.contains(name);
        let flags = FS_PROTECT_MUTATE
            | if ETC_WRITE_DENY_FILES.contains(name) {
                FS_PROTECT_WRITE
            } else {
                0
            }
            | if read_deny { FS_PROTECT_READ } else { 0 };
        register_inode(ebpf, &key, flags)
            .with_context(|| format!("registering {} in {PROTECTED_INODES_MAP}", path.display()))?;
        crate::fs_type::note_identity(&path);
        if read_deny {
            read_protected.push(key.ino);
        }
        info!(
            path = %path.display(),
            kernel_dev = key.dev,
            ino = key.ino,
            write_deny = flags & FS_PROTECT_WRITE != 0,
            "anti-tamper FS: /etc/northnarrow file registered in {PROTECTED_INODES_MAP}"
        );
        registered += 1;
    }
    if let Err(e) = set_read_protected(ebpf, &read_protected) {
        warn!(
            error = %e,
            "anti-tamper FS: the read-protected inodes could not be set — the signing key \
             stays readable by root this boot"
        );
    }
    info!(
        etc_dir = %etc_dir.display(),
        registered,
        read_protected = read_protected.len(),
        total = ETC_PROTECTED_FILES.len() + 1, // + the directory inode
        "anti-tamper FS: /etc/northnarrow file registration complete"
    );
    Ok(registered)
}

/// External audit EVD-001: the inode numbers the `file_open` deny matches
/// a read-only open against ([`READ_PROTECTED_INOS_MAP`]); the slots past
/// `inos` are cleared, so a key replaced since an earlier boot is not
/// matched by its old number.
fn set_read_protected(ebpf: &mut Ebpf, inos: &[u64]) -> Result<()> {
    let map = ebpf
        .map_mut(READ_PROTECTED_INOS_MAP)
        .ok_or_else(|| anyhow!("map {READ_PROTECTED_INOS_MAP} missing from eBPF object"))?;
    let mut array: aya::maps::Array<&mut MapData, u64> = aya::maps::Array::try_from(map)
        .with_context(|| format!("{READ_PROTECTED_INOS_MAP} is not an Array<u64>"))?;
    for slot in 0..READ_PROTECTED_SLOTS {
        let ino = inos.get(slot as usize).copied().unwrap_or(0);
        array.set(slot, ino, 0)?;
    }
    Ok(())
}

const READ_PROTECTED_INOS_MAP: &str = "READ_PROTECTED_INOS";

/// Review 81: register the sealed archives and the manifest of the chain
/// log whose active file is `active`, like the active file (WRITE+MUTATE).
/// Without it, a restart left every archive sealed by an earlier boot, and
/// every manifest, writable by root: the evidence the chain verification
/// exists to keep could be altered, and only found out afterwards. The
/// number of files registered.
fn register_sealed(ebpf: &mut Ebpf, active: &Path) -> Result<usize> {
    let mut n = 0usize;
    for path in crate::chainlog::sealed_files(active) {
        let meta = match own_entry_meta(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let key = InodeKey {
            dev: stat_dev_to_kernel_dev(meta.dev()),
            ino: meta.ino(),
        };
        register_inode(ebpf, &key, FS_PROTECT_MUTATE | FS_PROTECT_WRITE)
            .with_context(|| format!("registering {} in {PROTECTED_INODES_MAP}", path.display()))?;
        crate::fs_type::note_identity(&path);
        n += 1;
    }
    if n > 0 {
        info!(
            active = %active.display(),
            sealed = n,
            "anti-tamper FS: sealed archives and manifest registered in {PROTECTED_INODES_MAP}"
        );
    }
    Ok(n)
}

/// Tappa 9 C7: register each of the two [`STATE_PROTECTED_FILES`]
/// in `PROTECTED_INODES` so the same LSM hooks that defend
/// `/var/lib/northnarrow/` itself also defend the chained
/// `fim_baseline.jsonl` + `fim_drift.jsonl` files inside it.
/// Missing files are skipped with a warn (a fresh install before
/// the first baseline pass has no `fim_baseline.jsonl` yet); the
/// next agent restart after the baseline runs picks them up.
///
/// Returns the number of files actually registered, for the
/// info-log line.
pub(crate) fn register_state_files(ebpf: &mut Ebpf, state_dir: &Path) -> Result<usize> {
    let mut registered = 0usize;
    for name in STATE_PROTECTED_FILES {
        let path = state_dir.join(name);
        let meta = match own_entry_meta(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                warn!(
                    path = %path.display(),
                    "anti-tamper FS: skip register_state_files entry — file missing \
                     (will be unprotected until next agent restart with the file present)"
                );
                continue;
            }
            Err(e) => {
                warn!(
                    error = %e,
                    path = %path.display(),
                    "anti-tamper FS: stat failed for register_state_files entry"
                );
                continue;
            }
        };
        let key = InodeKey {
            dev: stat_dev_to_kernel_dev(meta.dev()),
            ino: meta.ino(),
        };
        // at-authz-1: the integrity chains are agent-append-only — WRITE+MUTATE.
        register_inode(ebpf, &key, FS_PROTECT_MUTATE | FS_PROTECT_WRITE)
            .with_context(|| format!("registering {} in {PROTECTED_INODES_MAP}", path.display()))?;
        crate::fs_type::note_identity(&path);
        info!(
            path = %path.display(),
            kernel_dev = key.dev,
            ino = key.ino,
            "anti-tamper FS: /var/lib/northnarrow FIM log registered in {PROTECTED_INODES_MAP}"
        );
        registered += 1 + register_sealed(ebpf, &path)?;
    }
    // Sub-directory chains (chain-protect-1): the directory inode first,
    // then its files. A missing dir/file is skipped like the entries
    // above (the detection store creates them lazily on first write).
    let mut subdir_total = 0usize;
    for (sub, files) in STATE_PROTECTED_SUBDIRS {
        subdir_total += 1 + files.len();
        let dir = state_dir.join(sub);
        // External audit ATP-007: the sub-directory itself, never a link's
        // target (`refuse_linked_state_dir` already refused one at boot).
        match std::fs::symlink_metadata(&dir) {
            Ok(meta) if meta.is_dir() => {
                let key = InodeKey {
                    dev: stat_dev_to_kernel_dev(meta.dev()),
                    ino: meta.ino(),
                };
                register_inode(ebpf, &key, PROTECTED_DIR_FLAGS).with_context(|| {
                    format!(
                        "registering subdir {} in {PROTECTED_INODES_MAP}",
                        dir.display()
                    )
                })?;
                crate::fs_type::note_identity(&dir);
                info!(
                    path = %dir.display(),
                    kernel_dev = key.dev,
                    ino = key.ino,
                    "anti-tamper FS: state sub-directory inode registered in {PROTECTED_INODES_MAP}"
                );
                registered += 1;
            }
            _ => {
                warn!(
                    path = %dir.display(),
                    "anti-tamper FS: state sub-directory missing (or not a directory: a link is \
                     not followed) — its chain logs are unprotected until the next agent restart \
                     with the directory present"
                );
                continue;
            }
        }
        for name in files.iter() {
            let path = dir.join(name);
            let meta = match own_entry_meta(&path) {
                Ok(m) => m,
                Err(e) => {
                    warn!(
                        error = %e,
                        path = %path.display(),
                        "anti-tamper FS: skip sub-directory chain log — missing/unreadable"
                    );
                    continue;
                }
            };
            let key = InodeKey {
                dev: stat_dev_to_kernel_dev(meta.dev()),
                ino: meta.ino(),
            };
            register_inode(ebpf, &key, FS_PROTECT_MUTATE | FS_PROTECT_WRITE).with_context(
                || format!("registering {} in {PROTECTED_INODES_MAP}", path.display()),
            )?;
            crate::fs_type::note_identity(&path);
            info!(
                path = %path.display(),
                kernel_dev = key.dev,
                ino = key.ino,
                "anti-tamper FS: sub-directory chain log registered in {PROTECTED_INODES_MAP}"
            );
            registered += 1 + register_sealed(ebpf, &path)?;
        }
    }
    info!(
        state_dir = %state_dir.display(),
        registered,
        total = STATE_PROTECTED_FILES.len() + subdir_total,
        "anti-tamper FS: /var/lib/northnarrow FIM-log registration complete"
    );
    Ok(registered)
}

/// Tappa 9.5 K7: register each of the five
/// [`ETC_PROTECTED_TEMPLATES`] in `PROTECTED_INODES` so the same
/// LSM hooks that defend `/etc/northnarrow/` files also defend
/// the K4 canary content templates. Missing files are skipped
/// with a warn (a fresh install before `install.sh` has dropped
/// the templates, or an operator who's deleted an unused family
/// to avoid future-renderer confusion); the next agent restart
/// after the file appears picks them up.
///
/// Returns the number of files actually registered, for the
/// info-log line.
pub(crate) fn register_etc_templates(ebpf: &mut Ebpf, etc_dir: &Path) -> Result<usize> {
    let mut registered = 0usize;
    let templates_dir = etc_dir.join(CANARY_TEMPLATES_SUBDIR);
    for name in ETC_PROTECTED_TEMPLATES {
        let path = templates_dir.join(name);
        let meta = match own_entry_meta(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                warn!(
                    path = %path.display(),
                    "anti-tamper FS: skip register_etc_templates entry — file missing \
                     (will be unprotected until next agent restart with the file present)"
                );
                continue;
            }
            Err(e) => {
                warn!(
                    error = %e,
                    path = %path.display(),
                    "anti-tamper FS: stat failed for register_etc_templates entry"
                );
                continue;
            }
        };
        let key = InodeKey {
            dev: stat_dev_to_kernel_dev(meta.dev()),
            ino: meta.ino(),
        };
        // at-authz-1: canary templates are operator-tunable content —
        // MUTATE-only (a live edit must not WRITE-deny-trip COMBAT).
        register_inode(ebpf, &key, FS_PROTECT_MUTATE)
            .with_context(|| format!("registering {} in {PROTECTED_INODES_MAP}", path.display()))?;
        crate::fs_type::note_identity(&path);
        info!(
            path = %path.display(),
            kernel_dev = key.dev,
            ino = key.ino,
            "anti-tamper FS: canary template registered in {PROTECTED_INODES_MAP}"
        );
        registered += 1;
    }
    info!(
        templates_dir = %templates_dir.display(),
        registered,
        total = ETC_PROTECTED_TEMPLATES.len(),
        "anti-tamper FS: canary template registration complete"
    );
    Ok(registered)
}

/// Stat each absolute path in `paths`, returning the
/// `(path, InodeKey)` pairs for the ones that currently exist. Missing
/// files (`NotFound`) are skipped with a warn — NOT fatal — so a host
/// that lacks, say, the watchdog binary still arms protection for the
/// paths it does have (mirrors the lenient skip in
/// [`register_etc_files`]). Any other stat error is likewise skipped
/// with a warn.
///
/// Factored out of [`register_binary_and_units`] as a pure
/// (no-`Ebpf`) helper so the skip-not-fatal resolution is
/// unit-testable without a live kernel map; the caller feeds each
/// returned key through the shared [`register_inode`] helper.
fn resolve_protected_paths(paths: &[&str]) -> Vec<(PathBuf, InodeKey)> {
    let mut resolved = Vec::with_capacity(paths.len());
    for &p in paths {
        let path = PathBuf::from(p);
        // External audit ATP-007: a NOCREATE directory is the directory
        // itself or nothing — a link there would give its target the
        // no-new-entry deny (`attach` refuses the start for it).
        if NOCREATE_UNIT_DIRS.contains(&p) {
            if let Some(link) = link_at(&path) {
                error!(
                    link = %link,
                    "anti-tamper FS: the agent's drop-in directory is a symbolic link — not \
                     followed, not registered"
                );
                continue;
            }
        }
        let meta = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Review 26: the list spans both install layouts, so the
                // other layout's paths are absent by design. A host with
                // neither copy is reported once by the caller.
                debug!(
                    path = %path.display(),
                    "anti-tamper FS: binary/unit path not present (other install layout)"
                );
                continue;
            }
            Err(e) => {
                warn!(
                    error = %e,
                    path = %path.display(),
                    "anti-tamper FS: stat failed for register_binary_and_units entry"
                );
                continue;
            }
        };
        resolved.push((
            path,
            InodeKey {
                dev: stat_dev_to_kernel_dev(meta.dev()),
                ino: meta.ino(),
            },
        ));
    }
    resolved
}

/// Register each of the [`BINARY_AND_UNIT_PATHS`] in `PROTECTED_INODES`
/// so the five `inode_*` / `file_ioctl` LSM deny hooks defend the
/// agent + watchdog executables and their systemd units exactly as
/// they defend the [`ETC_PROTECTED_FILES`] identity files. Modelled on
/// [`register_etc_files`]; reuses the shared [`register_inode`] helper.
///
/// Modification-only by construction — the LSM hooks deny
/// `unlink` / `rmdir` / `rename` / `setattr` (chmod, chown, truncate) /
/// `ioctl` (chattr) but NOT read or exec — so the agent still execs
/// its own binary and the init system still reads the unit files. NO
/// `chattr +i` (see [`BINARY_AND_UNIT_PATHS`]). Missing paths are
/// skipped (not fatal) via [`resolve_protected_paths`].
///
/// Returns the number actually registered, for the info-log line.
/// Review entry 39 — the pin root and every pin under it (maps, LSM
/// programs and links) join the protected-inode set with `FS_PROTECT_MUTATE`:
/// unlink, rmdir, rename and setattr are denied to any caller that is not
/// a protected pid, unless the trusted-installer override window is open.
/// Before this, `systemctl stop` of both units (the PID-1 carve-out allows
/// it) followed by `rm -rf /sys/fs/bpf/northnarrow` dropped every hook.
/// Called once all pins of this boot exist; the next boot's agent is a
/// protected pid when it purges the stale pins, so the fresh re-attach is
/// unaffected. `install.sh --upgrade` / `uninstall.sh` open the window
/// (`--grant-key`) before they purge. The root takes
/// [`PROTECTED_DIR_FLAGS`] (external audit EBPF-015): a pin by a foreign
/// process is refused like any new entry.
pub(crate) fn register_bpffs_pins(ebpf: &mut Ebpf, pin_root: &Path) -> Result<usize> {
    let mut registered = 0usize;
    let mut paths: Vec<PathBuf> = vec![pin_root.to_path_buf()];
    let entries = std::fs::read_dir(pin_root)
        .with_context(|| format!("listing the pin root {}", pin_root.display()))?;
    for entry in entries.flatten() {
        paths.push(entry.path());
    }
    for path in &paths {
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, path = %path.display(), "anti-tamper FS: cannot stat a bpffs pin — not protected");
                continue;
            }
        };
        let key = InodeKey {
            dev: stat_dev_to_kernel_dev(meta.dev()),
            ino: meta.ino(),
        };
        // External audit EBPF-015: the root also refuses new entries — a
        // pin (`bpf_obj_pin` creates through `inode_create`) or a directory
        // planted among the agent's.
        let flags = if path == pin_root {
            PROTECTED_DIR_FLAGS
        } else {
            FS_PROTECT_MUTATE
        };
        register_inode(ebpf, &key, flags).with_context(|| {
            format!(
                "registering pin {} in {PROTECTED_INODES_MAP}",
                path.display()
            )
        })?;
        registered += 1;
    }
    info!(
        registered,
        root = %pin_root.display(),
        "anti-tamper FS: bpffs pin root and pins registered in {PROTECTED_INODES_MAP} — unlink/rename and \
         new pins denied to foreign callers (trusted-installer window to purge)"
    );
    Ok(registered)
}

/// The `PROTECTED_INODES` flags of one of [`BINARY_AND_UNIT_PATHS`]:
/// WRITE+MUTATE, plus NOCREATE for the agent's own drop-in directory
/// ([`NOCREATE_UNIT_DIRS`], external audit EBPF-015).
fn binary_or_unit_flags(path: &Path) -> u8 {
    let nocreate = NOCREATE_UNIT_DIRS.iter().any(|d| path == Path::new(d));
    FS_PROTECT_MUTATE | FS_PROTECT_WRITE | if nocreate { FS_PROTECT_NOCREATE } else { 0 }
}

pub(crate) fn register_binary_and_units(ebpf: &mut Ebpf) -> Result<usize> {
    let mut registered = 0usize;
    let resolved = resolve_protected_paths(BINARY_AND_UNIT_PATHS);
    let present = |name: &str| resolved.iter().any(|(p, _)| p.ends_with(name));
    if !present("northnarrow-agent") || !present("northnarrow-agent.service") {
        warn!(
            candidates = %BINARY_AND_UNIT_PATHS.join(", "),
            "anti-tamper FS: the agent binary or unit is in neither install layout — \
             unprotected until the next agent restart with it present"
        );
    }
    for (path, key) in resolved {
        // at-authz-1: the agent/watchdog images + units are agent-written
        // (signed self-upgrade, exempt via the trusted-installer window, FS_GRANT) — WRITE+MUTATE.
        register_inode(ebpf, &key, binary_or_unit_flags(&path))
            .with_context(|| format!("registering {} in {PROTECTED_INODES_MAP}", path.display()))?;
        crate::fs_type::note_identity(&path);
        info!(
            path = %path.display(),
            kernel_dev = key.dev,
            ino = key.ino,
            "anti-tamper FS: agent binary/unit registered in {PROTECTED_INODES_MAP}"
        );
        registered += 1;
    }
    info!(
        registered,
        total = BINARY_AND_UNIT_PATHS.len(),
        "anti-tamper FS: agent binary/unit registration complete"
    );
    Ok(registered)
}

/// Tappa 9.5 K7: bootstrap an empty canary state log file
/// (either `canaries.jsonl` or `canary_access.jsonl`) if it
/// doesn't exist yet, so PROTECTED_INODES has an inode to
/// register at attach time. Same shape as [`bootstrap_fim_log`]
/// — parent directory's mode is 0700 to match [`STATE_DIR_MODE`].
pub fn bootstrap_canary_log(canary_log_path: &Path) -> Result<()> {
    if canary_log_path.exists() {
        return Ok(());
    }
    if let Some(parent) = canary_log_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            DirBuilder::new()
                .mode(STATE_DIR_MODE)
                .recursive(true)
                .create(parent)
                .with_context(|| format!("creating canary-log parent dir {}", parent.display()))?;
        }
    }
    // Root only (external audit EVD-019, STATE_LOG_FILE_MODE); the
    // LSM-enforced append-only applies via PROTECTED_INODES +
    // PROTECTED_PIDS exemption, same as the FIM logs.
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(crate::chainlog::STATE_LOG_FILE_MODE)
        .open(canary_log_path)
        .with_context(|| format!("creating canary log {}", canary_log_path.display()))?;
    info!(
        path = %canary_log_path.display(),
        "anti-tamper FS: canary log bootstrapped (zero-byte placeholder for PROTECTED_INODES)"
    );
    Ok(())
}

/// External audit NN-AUD-108 (lab PR 160): bootstrap the empty head
/// anchor (`chain_heads.json`, next to the audit log) so
/// `PROTECTED_INODES` has its inode at attach time. Same contract as
/// [`bootstrap_audit_log`]: a present file is left untouched.
pub fn bootstrap_chain_heads(heads_path: &Path) -> Result<()> {
    if heads_path.exists() {
        return Ok(());
    }
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(crate::chain_anchor::HEADS_FILE_MODE)
        .open(heads_path)
        .with_context(|| format!("creating chain heads {}", heads_path.display()))?;
    info!(
        path = %heads_path.display(),
        "anti-tamper FS: chain heads bootstrapped (zero-byte placeholder for PROTECTED_INODES)"
    );
    Ok(())
}

/// Tappa 10 N9: bootstrap an empty NetListener log file
/// (`netflow_listeners.jsonl`) if it doesn't exist yet, so
/// PROTECTED_INODES has an inode to register at attach time.
/// Same shape as [`bootstrap_netflow_log`] — parent directory's
/// mode is 0700 to match [`STATE_DIR_MODE`].
pub fn bootstrap_netflow_listeners_log(listeners_log_path: &Path) -> Result<()> {
    if listeners_log_path.exists() {
        return Ok(());
    }
    if let Some(parent) = listeners_log_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            DirBuilder::new()
                .mode(STATE_DIR_MODE)
                .recursive(true)
                .create(parent)
                .with_context(|| {
                    format!(
                        "creating netflow_listeners-log parent dir {}",
                        parent.display()
                    )
                })?;
        }
    }
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(crate::chainlog::STATE_LOG_FILE_MODE)
        .open(listeners_log_path)
        .with_context(|| {
            format!(
                "creating netflow_listeners log {}",
                listeners_log_path.display()
            )
        })?;
    info!(
        path = %listeners_log_path.display(),
        "anti-tamper FS: netflow_listeners log bootstrapped (zero-byte placeholder for PROTECTED_INODES)"
    );
    Ok(())
}

/// Tappa 10 N8: bootstrap an empty NetFlow log file
/// (`netflow.jsonl`) if it doesn't exist yet, so PROTECTED_INODES
/// has an inode to register at attach time. Same shape as
/// [`bootstrap_fim_log`] + [`bootstrap_canary_log`] — parent
/// directory's mode is 0700 to match [`STATE_DIR_MODE`].
pub fn bootstrap_netflow_log(netflow_log_path: &Path) -> Result<()> {
    if netflow_log_path.exists() {
        return Ok(());
    }
    if let Some(parent) = netflow_log_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            DirBuilder::new()
                .mode(STATE_DIR_MODE)
                .recursive(true)
                .create(parent)
                .with_context(|| format!("creating netflow-log parent dir {}", parent.display()))?;
        }
    }
    // Root only (external audit EVD-019, STATE_LOG_FILE_MODE); the
    // LSM-enforced append-only applies via PROTECTED_INODES +
    // PROTECTED_PIDS exemption, same as the FIM + canary logs.
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(crate::chainlog::STATE_LOG_FILE_MODE)
        .open(netflow_log_path)
        .with_context(|| format!("creating netflow log {}", netflow_log_path.display()))?;
    info!(
        path = %netflow_log_path.display(),
        "anti-tamper FS: netflow log bootstrapped (zero-byte placeholder for PROTECTED_INODES)"
    );
    Ok(())
}

/// Tappa 9 C7: bootstrap an empty FIM log file (either
/// `fim_baseline.jsonl` or `fim_drift.jsonl`) if it doesn't
/// exist yet, so PROTECTED_INODES has an inode to register at
/// attach time. Same shape as [`bootstrap_audit_log`] but the
/// parent directory's mode is 0700 to match [`STATE_DIR_MODE`]
/// rather than the 0755 of `/etc/northnarrow/`.
pub fn bootstrap_fim_log(fim_log_path: &Path) -> Result<()> {
    if fim_log_path.exists() {
        return Ok(());
    }
    if let Some(parent) = fim_log_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            DirBuilder::new()
                .mode(STATE_DIR_MODE)
                .recursive(true)
                .create(parent)
                .with_context(|| format!("creating fim-log parent dir {}", parent.display()))?;
        }
    }
    // Root only (external audit EVD-019, STATE_LOG_FILE_MODE); the
    // LSM-enforced append-only applies via PROTECTED_INODES +
    // PROTECTED_PIDS exemption.
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(crate::chainlog::STATE_LOG_FILE_MODE)
        .open(fim_log_path)
        .with_context(|| format!("creating fim log {}", fim_log_path.display()))?;
    info!(
        path = %fim_log_path.display(),
        "anti-tamper FS: fim log bootstrapped (zero-byte placeholder for PROTECTED_INODES)"
    );
    Ok(())
}

/// Tappa 9.0.a: bootstrap the detection chainlog's directory + an empty
/// active file pre-attach, so PROTECTED_INODES has an inode to register
/// before the LSM hooks come up — exactly as the FIM / netflow logs do.
/// Creates the `detections/` sub-dir at [`STATE_DIR_MODE`] (0700) if
/// missing, then a zero-byte 0600 active file. Idempotent: a present
/// file (existing chain) is left untouched.
pub fn bootstrap_detections_log(detections_log_path: &Path) -> Result<()> {
    if detections_log_path.exists() {
        return Ok(());
    }
    if let Some(parent) = detections_log_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            DirBuilder::new()
                .mode(STATE_DIR_MODE)
                .recursive(true)
                .create(parent)
                .with_context(|| {
                    format!("creating detections-log parent dir {}", parent.display())
                })?;
        }
    }
    // Root only (external audit EVD-019, STATE_LOG_FILE_MODE),
    // agent-writable (append-only enforced via PROTECTED_INODES + the
    // agent's PID exemption) — same envelope as the FIM drift log.
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(crate::chainlog::STATE_LOG_FILE_MODE)
        .open(detections_log_path)
        .with_context(|| format!("creating detections log {}", detections_log_path.display()))?;
    info!(
        path = %detections_log_path.display(),
        "anti-tamper FS: detections log bootstrapped (zero-byte placeholder for PROTECTED_INODES)"
    );
    Ok(())
}

/// Tappa 9.0.c: bootstrap the status-event chainlog
/// (`status_events.jsonl`) pre-attach — a sibling of the detection log
/// inside the same `detections/` dir, with the same zero-byte 0600
/// envelope. Idempotent: a present file (existing chain) is left
/// untouched.
///
/// NOTE on anti-tamper coverage: like its sibling `detections.jsonl`
/// (9.0.a), this file currently has NO entry in [`STATE_PROTECTED_FILES`]
/// — `register_state_files` joins each entry onto the top-level state
/// dir, so it cannot reach a file in the `detections/` SUBDIR, and the
/// subdir inode itself is not registered. So the FS-modification LSM
/// deny hooks do NOT yet protect these two files (the chain is still
/// Ed25519-signed, so tampering is at least detectable as a chain
/// break, and the dir is 0700). Closing this gap needs subdir-aware
/// `PROTECTED_INODES` registration covering BOTH files (a follow-up,
/// out of 9.0.c scope). The pre-attach bootstrap here keeps that future
/// registration cheap (the inode already exists).
pub fn bootstrap_status_events_log(status_events_log_path: &Path) -> Result<()> {
    if status_events_log_path.exists() {
        return Ok(());
    }
    if let Some(parent) = status_events_log_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            DirBuilder::new()
                .mode(STATE_DIR_MODE)
                .recursive(true)
                .create(parent)
                .with_context(|| {
                    format!("creating status-events-log parent dir {}", parent.display())
                })?;
        }
    }
    // Root only (external audit EVD-019, STATE_LOG_FILE_MODE),
    // agent-writable. (NOT yet PROTECTED_INODES-registered — see the fn
    // doc-comment; same gap as the sibling detection log.)
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(crate::chainlog::STATE_LOG_FILE_MODE)
        .open(status_events_log_path)
        .with_context(|| {
            format!(
                "creating status-events log {}",
                status_events_log_path.display()
            )
        })?;
    info!(
        path = %status_events_log_path.display(),
        "anti-tamper FS: status-events log bootstrapped (zero-byte placeholder for PROTECTED_INODES)"
    );
    Ok(())
}

/// Tappa 8 A14 (B4): bootstrap an empty audit.log file if it
/// doesn't exist yet, so PROTECTED_INODES has an inode to
/// register at attach time. Idempotent: a present file is
/// untouched. Atomicity isn't critical here — the file is
/// 0 bytes either way; the worst race is a concurrent agent
/// starting up and observing a non-existent path moments
/// before we create it.
pub fn bootstrap_audit_log(audit_log_path: &Path) -> Result<()> {
    if audit_log_path.exists() {
        return Ok(());
    }
    if let Some(parent) = audit_log_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            DirBuilder::new()
                .mode(0o755)
                .recursive(true)
                .create(parent)
                .with_context(|| format!("creating audit-log parent dir {}", parent.display()))?;
        }
    }
    // 0640 (external audit EVD-019, AUDIT_LOG_FILE_MODE): root-only
    // writable + LSM-enforced append-only (design §6.5), readable by
    // root and the file's group only — no longer by every local user.
    // Empty file body — first append writes the genesis entry.
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(crate::audit::AUDIT_LOG_FILE_MODE)
        .open(audit_log_path)
        .with_context(|| format!("creating audit log {}", audit_log_path.display()))?;
    info!(
        path = %audit_log_path.display(),
        "anti-tamper FS: audit log bootstrapped (zero-byte placeholder for PROTECTED_INODES)"
    );
    Ok(())
}

/// The response executor's vault, `quarantine/vault` (mode 0700). Under
/// the state directory's `chattr +i` nobody — the agent included — adds an
/// entry to it: the first quarantine on a fresh install failed with EPERM
/// creating the vault (lab, external audit CMB-001 verification). Created
/// here at every start when missing, with `+i` lifted for the moment it
/// takes when a previous boot set it ([`ImmutabilityGuard`] re-applies it).
fn ensure_quarantine_dirs(dir: &Path) -> Result<()> {
    let quarantine = dir.join("quarantine");
    let vault = quarantine.join("vault");
    // External audit ATP-007: a link at either is refused, not followed
    // (`refuse_linked_state_dir` stops the start before this runs).
    for p in [&quarantine, &vault] {
        if let Some(link) = link_at(p) {
            return Err(anyhow!("{link}: the vault is not created through a link"));
        }
    }
    let is_dir = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir());
    if is_dir(&vault) {
        return Ok(());
    }
    // only the state dir itself carries +i: an existing quarantine/ takes
    // its vault without lifting anything
    let _guard = if is_dir(&quarantine) {
        None
    } else {
        Some(ImmutabilityGuard::lift(dir)?)
    };
    DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(&vault)
        .with_context(|| format!("mkdir {}", vault.display()))?;
    Ok(())
}

/// External audit ATP-007 (NN-AUD-260): the entries of the state
/// directory the agent keeps there itself and registers or writes by path —
/// the quarantine vault and its parent, the chain sub-directories and their
/// logs, the flat chain logs. No install makes any of them a symbolic link:
/// one there was planted by a root before the agent started.
fn state_dir_own_entries() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = vec![
        PathBuf::from("quarantine"),
        PathBuf::from("quarantine/vault"),
    ];
    v.extend(STATE_PROTECTED_FILES.iter().map(PathBuf::from));
    for (sub, files) in STATE_PROTECTED_SUBDIRS {
        v.push(PathBuf::from(sub));
        v.extend(files.iter().map(|f| Path::new(sub).join(f)));
    }
    v
}

/// `"<path> -> <target>"` when `path` itself is a symbolic link (its final
/// component; `lstat`), else `None`.
fn link_at(path: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    meta.file_type().is_symlink().then(|| {
        let target = std::fs::read_link(path)
            .map(|t| t.display().to_string())
            .unwrap_or_else(|_| "?".to_string());
        format!("{} -> {target}", path.display())
    })
}

/// External audit ATP-007 (NN-AUD-260): refuse a state directory reached
/// through a symbolic link, or one holding a link where the agent keeps its
/// own entries ([`state_dir_own_entries`]). The agent repairs the
/// directory's mode (0700) and owner (root) and registers it with
/// [`PROTECTED_DIR_FLAGS`] — no new entry, no unlink or rename outside a
/// trusted-installer window — so a link planted at `/var/lib/northnarrow`
/// gave all of that to its target (`/etc` would have refused every new
/// file), and the agent's evidence went into it. Called first thing at
/// boot, before anything reads or writes the directory, and again by
/// [`attach`] before the registration. A missing directory is fine: the
/// attach creates it.
pub fn refuse_linked_state_dir(dir: &Path) -> Result<()> {
    let links: Vec<String> = match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(anyhow!(e).context(format!("lstat {}", dir.display()))),
        Ok(m) if m.file_type().is_symlink() => link_at(dir).into_iter().collect(),
        Ok(m) if !m.is_dir() => {
            return Err(anyhow!("{} exists and is not a directory", dir.display()))
        }
        Ok(_) => state_dir_own_entries()
            .iter()
            .filter_map(|e| link_at(&dir.join(e)))
            .collect(),
    };
    if links.is_empty() {
        return Ok(());
    }
    Err(anyhow!(
        "the state directory {} is reached through a symbolic link, or holds one where the agent \
         keeps its own entries ({}): refusing to start. The agent does not follow a link there — \
         it would give the link's target the directory's protection (mode 0700, owner root, no new \
         entry, no unlink or rename) and write its evidence into it. Put the real directory back; \
         to keep the state on another filesystem, bind-mount that directory at {} (upgrade notes \
         of external audit 16f7563, §2)",
        dir.display(),
        links.join(", "),
        dir.display()
    ))
}

/// The state directory, ready to register: [`refuse_linked_state_dir`],
/// then [`ensure_own_dir`] with mode 0700 and owner root.
fn ensure_state_dir(dir: &Path) -> Result<std::fs::Metadata> {
    refuse_linked_state_dir(dir)?;
    ensure_own_dir(dir, STATE_DIR_MODE, 0, 0)
}

/// Create `dir` (`mode`; an existing one is fine), then open the directory
/// itself — `O_NOFOLLOW | O_DIRECTORY`, never through a link at its final
/// component — and repair its mode and owner on that descriptor (`fchmod`,
/// `fchown`). External audit ATP-007: `metadata`, `set_permissions` and
/// `chown` by path all followed a link. The metadata returned is the
/// descriptor's (`fstat`), taken after the repair: the inode the caller
/// registers is the one repaired, whatever the path names by then.
fn ensure_own_dir(dir: &Path, mode: u32, uid: u32, gid: u32) -> Result<std::fs::Metadata> {
    // Try to create; tolerate AlreadyExists (idempotent startup).
    match DirBuilder::new().mode(mode).recursive(true).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(anyhow!(e).context(format!("mkdir {}", dir.display()))),
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(dir)
        .map_err(|e| match link_at(dir) {
            Some(link) => {
                anyhow!("{link}: the agent does not follow a symbolic link at its own directory")
            }
            None => {
                anyhow!(e).context(format!("open {} (O_NOFOLLOW | O_DIRECTORY)", dir.display()))
            }
        })?;
    let meta = file
        .metadata()
        .with_context(|| format!("fstat {} after mkdir", dir.display()))?;

    // Re-assert ownership + mode unconditionally so a slack umask
    // or a previous-version run with wider perms doesn't persist.
    let mut repaired = false;
    if (meta.mode() & 0o7777) != mode {
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("fchmod {mode:o} {}", dir.display()))?;
        repaired = true;
    }
    if meta.uid() != uid || meta.gid() != gid {
        std::os::unix::fs::fchown(&file, Some(uid), Some(gid))
            .with_context(|| format!("fchown {uid}:{gid} {}", dir.display()))?;
        repaired = true;
    }
    if !repaired {
        return Ok(meta);
    }
    file.metadata()
        .with_context(|| format!("fstat {} after the repair", dir.display()))
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
pub(crate) fn stat_dev_to_kernel_dev(st_dev: u64) -> u64 {
    let major = libc::major(st_dev) as u64;
    let minor = libc::minor(st_dev) as u64;
    (major << 20) | minor
}

/// Review 63: the keys this boot registered, for [`prune_stale_inodes`].
static BOOT_KEYS: parking_lot::Mutex<Option<std::collections::HashSet<(u64, u64)>>> =
    parking_lot::Mutex::new(None);

/// Insert `key` into `PROTECTED_INODES` with the at-authz-1 `flags`
/// mask (`FS_PROTECT_MUTATE` and/or `FS_PROTECT_WRITE`). The map value
/// records which deny classes apply to this inode so the eBPF
/// `deny_if_protected` can be op-aware (the write-open deny covers only
/// the `FS_PROTECT_WRITE` subset). An existing entry is overwritten.
///
/// A full map (earlier boots' keys, review 63) is pruned of everything
/// this boot has not registered yet, then the insert is retried once:
/// a key the rest of the boot re-registers goes unprotected for a few
/// milliseconds, instead of the agent refusing to start.
fn register_inode(ebpf: &mut Ebpf, key: &InodeKey, flags: u8) -> Result<()> {
    if insert_inode(ebpf, key, flags).is_err() {
        let pruned = prune_stale_inodes(ebpf)?;
        warn!(
            pruned,
            "anti-tamper FS: {PROTECTED_INODES_MAP} full — keys of earlier boots pruned \
             before this boot finished registering"
        );
        insert_inode(ebpf, key, flags).with_context(|| {
            format!(
                "inserting (dev={}, ino={}) into {PROTECTED_INODES_MAP}",
                key.dev, key.ino
            )
        })?;
    }
    BOOT_KEYS
        .lock()
        .get_or_insert_with(Default::default)
        .insert((key.dev, key.ino));
    Ok(())
}

fn insert_inode(ebpf: &mut Ebpf, key: &InodeKey, flags: u8) -> Result<()> {
    let map = ebpf
        .map_mut(PROTECTED_INODES_MAP)
        .ok_or_else(|| anyhow!("map {PROTECTED_INODES_MAP} missing from eBPF object"))?;
    let mut map: AyaHashMap<&mut MapData, AyaInodeKey, u8> = AyaHashMap::try_from(map)
        .with_context(|| format!("{PROTECTED_INODES_MAP} is not a HashMap<InodeKey, u8>"))?;
    map.insert(AyaInodeKey(*key), flags, 0)?;
    Ok(())
}

/// Review 63: remove every `PROTECTED_INODES` key this boot has not
/// registered. The map is pinned, so it outlives the agent, and every
/// boot brings new inodes: the bpffs pins of the hooks reattached fresh,
/// rotated logs, replaced files. Without this the earlier boots' keys
/// piled up (23 per restart on the lab) until an insert failed at 1024,
/// some 41 restarts into one uptime, and the agent refused to start.
/// Called once every registration is done (the pins last), so new keys
/// are in before stale ones go: no window. The number of keys removed.
pub(crate) fn prune_stale_inodes(ebpf: &mut Ebpf) -> Result<usize> {
    let keep = BOOT_KEYS.lock().clone().unwrap_or_default();
    let map = ebpf
        .map_mut(PROTECTED_INODES_MAP)
        .ok_or_else(|| anyhow!("map {PROTECTED_INODES_MAP} missing from eBPF object"))?;
    let mut map: AyaHashMap<&mut MapData, AyaInodeKey, u8> = AyaHashMap::try_from(map)
        .with_context(|| format!("{PROTECTED_INODES_MAP} is not a HashMap<InodeKey, u8>"))?;
    let stale: Vec<AyaInodeKey> = map
        .keys()
        .filter_map(|k| k.ok())
        .filter(|k| !keep.contains(&(k.0.dev, k.0.ino)))
        .collect();
    for k in &stale {
        let _ = map.remove(k);
    }
    Ok(stale.len())
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

// ── BUG-026 — rotation dance: lift immutability fail-safe ────────────

/// Clear `FS_IMMUTABLE_FL` (the inverse of [`chattr_immutable_add`]).
/// `Ok(true)` if the bit was set and is now cleared, `Ok(false)` if it
/// was already clear. Used ONLY through [`ImmutabilityGuard`], which
/// guarantees a paired re-add.
fn chattr_immutable_remove(path: &Path) -> Result<bool> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open {} for chattr -i", path.display()))?;
    let fd = file.as_raw_fd();
    let mut flags: libc::c_long = 0;
    // SAFETY: `flags` is a valid c_long lvalue; fd is owned.
    let rc = unsafe { libc::ioctl(fd, FS_IOC_GETFLAGS, &mut flags) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("FS_IOC_GETFLAGS on {}", path.display()));
    }
    if flags & FS_IMMUTABLE_FL == 0 {
        return Ok(false);
    }
    flags &= !FS_IMMUTABLE_FL;
    // SAFETY: same `flags` pointer, read by the kernel.
    let rc = unsafe { libc::ioctl(fd, FS_IOC_SETFLAGS, &flags) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("FS_IOC_SETFLAGS (clear immutable) on {}", path.display()));
    }
    Ok(true)
}

/// RAII fail-safe for the BUG-026 rotation dance. Construction
/// (`lift`) drops `chattr +i` on the state dir; `Drop` RE-APPLIES it on
/// EVERY exit path — `Ok`, `Err`, or panic/unwind — so a failed or
/// interrupted rotation can never leave the directory mutable. The
/// re-add is idempotent (`chattr_immutable_add` no-ops if already set),
/// so this also HEALS a directory found already-mutable (e.g. a crash
/// mid-dance on a prior boot). If `lift` itself fails, no guard is
/// constructed and the dir stays `+i` — the caller aborts the rotation.
/// Backstop: the boot-time `chattr_immutable_add` (run on every start,
/// `prepare_state_dir` Step 3) re-asserts `+i` even if a process died
/// with the bit cleared and Drop never ran.
struct ImmutabilityGuard<'a> {
    dir: &'a Path,
}

impl<'a> ImmutabilityGuard<'a> {
    fn lift(dir: &'a Path) -> Result<Self> {
        chattr_immutable_remove(dir)
            .with_context(|| format!("lifting immutability on {}", dir.display()))?;
        Ok(Self { dir })
    }
}

impl Drop for ImmutabilityGuard<'_> {
    fn drop(&mut self) {
        // Cannot propagate from Drop — re-assert +i, retrying a few times
        // to shrink the mutable window on a transient ioctl failure before
        // the loud error. No sleep (Drop must stay quick); the boot
        // self-heal is the ultimate backstop.
        let mut last_err = None;
        for _ in 0..4 {
            match chattr_immutable_add(self.dir) {
                Ok(_) => return,
                Err(e) => last_err = Some(e),
            }
        }
        if let Some(e) = last_err {
            tracing::error!(
                error = %e,
                path = %self.dir.display(),
                "anti-tamper FS: FAILED to restore chattr +i after rotation (4 attempts) — \
                 directory is MUTABLE until the next agent restart re-applies it \
                 (boot self-heal backstop)"
            );
        }
    }
}

/// Owned writable handle to the pinned `PROTECTED_INODES` map, for
/// registering a freshly-rotated active file's inode so the LSM
/// defends it like its predecessor. Same `take_map` idiom as the FIM
/// `WatchedPathsHandle`. NOTE (wiring caveat for the writer-migration
/// step): take this AFTER `prepare_state_dir` finishes its
/// registrations, and confirm no other post-bootstrap path mutates
/// `PROTECTED_INODES` via the `Ebpf` handle (else prefer opening the
/// pin by path instead of `take_map`).
pub struct ProtectedInodesHandle {
    map: AyaHashMap<MapData, AyaInodeKey, u8>,
}

impl ProtectedInodesHandle {
    /// Open the by-name-pinned `PROTECTED_INODES` map directly from bpffs,
    /// independent of the `Ebpf` object whose handle `StateDirProtection`
    /// already owns. Lets a runtime caller (the rotate-keys dispatchers)
    /// re-register an inode without threading a handle through the admin
    /// socket. Mirrors the `MapData::from_pin` idiom in
    /// `trusted_installer::write_fs_override` / `register_protected_observer`.
    pub fn open(bpffs_root: &Path) -> Result<Self> {
        let pin_path = bpffs_root.join(PROTECTED_INODES_MAP);
        let map_data = MapData::from_pin(&pin_path).with_context(|| {
            format!(
                "opening pinned {PROTECTED_INODES_MAP} at {}",
                pin_path.display()
            )
        })?;
        let map = AyaHashMap::<MapData, AyaInodeKey, u8>::try_from(AyaMap::HashMap(map_data))
            .with_context(|| format!("{PROTECTED_INODES_MAP} is not a HashMap<InodeKey, u8>"))?;
        Ok(ProtectedInodesHandle { map })
    }

    pub fn register(&mut self, key: InodeKey, flags: u8) -> Result<()> {
        self.map
            .insert(AyaInodeKey(key), flags, 0)
            .with_context(|| {
                format!(
                    "registering (dev={}, ino={}) in {PROTECTED_INODES_MAP}",
                    key.dev, key.ino
                )
            })
    }

    /// Drop a stale inode key (best-effort at the call sites that use it):
    /// after a rename-replace the old inode is freed and its dev/ino could
    /// later be reused by an unrelated, non-protected file.
    /// `key` is in the map.
    pub fn contains(&self, key: InodeKey) -> bool {
        self.map.get(&AyaInodeKey(key), 0).is_ok()
    }

    pub fn remove(&mut self, key: InodeKey) -> Result<()> {
        self.map.remove(&AyaInodeKey(key)).with_context(|| {
            format!(
                "removing stale (dev={}, ino={}) from {PROTECTED_INODES_MAP}",
                key.dev, key.ino
            )
        })
    }
}

/// at-authz-1 verify-item 1: re-register a protected file's inode after a
/// rename-based rewrite. `atomic_rewrite_admin_pub_add/_revoke` write a
/// `.tmp` and `rename(2)` over admin.pub, which installs a NEW inode the
/// boot-time `register_etc_files` never saw — so every deny hook (the
/// existing five AND the at-authz-1 write-open deny) would lapse on the
/// rotated admin.pub until the next restart. This re-registers the new
/// inode with `flags` and drops the stale `old_key`.
///
/// `bpffs_root: None` ⇒ no pinned map this boot ⇒ no-op success (the
/// hooks aren't attached either, same degrade as the rest of the family).
/// The caller logs loudly on `Err` — a failure means the rotated file is
/// unprotected until restart.
pub fn reregister_protected_file(
    bpffs_root: Option<&Path>,
    path: &Path,
    old_key: Option<InodeKey>,
    flags: u8,
) -> Result<()> {
    let Some(root) = bpffs_root else {
        return Ok(());
    };
    let new_key = crate::fim::attach::key_for_path(path)
        .with_context(|| format!("stat {} for re-registration", path.display()))?;
    let mut handle = ProtectedInodesHandle::open(root)?;
    handle.register(new_key, flags)?;
    if let Some(old) = old_key {
        if old != new_key {
            // Best-effort: a missing old key (already gone) is fine.
            let _ = handle.remove(old);
        }
    }
    Ok(())
}

/// Take an owned writable `PROTECTED_INODES` handle out of the `Ebpf`
/// object (see the caveat on [`ProtectedInodesHandle`]).
pub fn take_protected_inodes_map(ebpf: &mut Ebpf) -> Result<ProtectedInodesHandle> {
    let map = ebpf
        .take_map(PROTECTED_INODES_MAP)
        .ok_or_else(|| anyhow!("map {PROTECTED_INODES_MAP} missing from eBPF object"))?;
    let map = AyaHashMap::<MapData, AyaInodeKey, u8>::try_from(map)
        .with_context(|| format!("{PROTECTED_INODES_MAP} is not a HashMap<InodeKey, u8>"))?;
    Ok(ProtectedInodesHandle { map })
}

/// Production [`crate::chainlog::ProtectionManager`] for logs that live
/// under the `chattr +i` / `PROTECTED_INODES` state dir. `with_mutable_dir`
/// lifts the directory's immutability via [`ImmutabilityGuard`]
/// (fail-safe restore on drop); `register_active` registers a
/// freshly-rotated active file's inode. Logs OUTSIDE the protected dir
/// (e.g. `combat-audit.jsonl`) use `chainlog::NoProtection` instead.
pub struct StateDirProtection {
    dir: PathBuf,
    /// Serializes the chattr dance across ALL writers that share this dir:
    /// `netflow.jsonl` + `fim_drift.jsonl` both live under
    /// `/var/lib/northnarrow` and share one `Arc<StateDirProtection>`, so
    /// two concurrent rotations would otherwise race on the dir's `+i`
    /// (A lifts `-i`, B lifts `-i`, A restores `+i` while B is mid-rename).
    /// Held for the WHOLE dance, so only one rotation holds the dir `-i`
    /// at a time. Normal appends never take it (they are `O_APPEND` on the
    /// file, not dir-entry ops) — only rotation's create/rename/unlink.
    dance: parking_lot::Mutex<()>,
    inodes: parking_lot::Mutex<ProtectedInodesHandle>,
}

impl StateDirProtection {
    pub fn new(dir: PathBuf, inodes: ProtectedInodesHandle) -> Self {
        Self {
            dir,
            dance: parking_lot::Mutex::new(()),
            inodes: parking_lot::Mutex::new(inodes),
        }
    }
}

impl crate::chainlog::ProtectionManager for StateDirProtection {
    fn with_mutable_dir(&self, f: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        // Serialize the dance first, THEN lift immutability. Drop order is
        // reverse-declaration: `_guard` drops before `_dance`, so `+i` is
        // restored BEFORE the lock releases — the next writer that
        // acquires the dance lock always finds the dir `+i`.
        let _dance = self.dance.lock();
        let _guard = ImmutabilityGuard::lift(&self.dir)?;
        f()
    }

    fn register_active(&self, path: &Path) -> Result<()> {
        let key = crate::fim::attach::key_for_path(path)?;
        // at-authz-1: rotated chain logs are integrity files — WRITE+MUTATE.
        self.inodes
            .lock()
            .register(key, FS_PROTECT_MUTATE | FS_PROTECT_WRITE)
    }

    fn release(&self, path: &Path) -> Result<()> {
        let key = crate::fim::attach::key_for_path(path)?;
        let mut inodes = self.inodes.lock();
        // An archive sealed before review 81 may have no key: nothing to drop.
        if inodes.contains(key) {
            inodes.remove(key)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn ids() -> (u32, u32) {
        // SAFETY: getuid/getgid cannot fail and touch no memory.
        unsafe { (libc::getuid(), libc::getgid()) }
    }

    /// External audit ATP-007 (NN-AUD-260): a state directory that is a
    /// link is refused, naming the link and its target, and the target is
    /// left as it was — mode, owner, entries. Before, `ensure_state_dir`
    /// chmodded it 0700 and the attach registered it NOCREATE.
    #[test]
    fn state_dir_symlink_is_refused_and_target_untouched() {
        let t = TempDir::new().unwrap();
        let real = t.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
        let before = std::fs::metadata(&real).unwrap();
        let link = t.path().join("northnarrow");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = format!("{:#}", ensure_state_dir(&link).unwrap_err());
        assert!(err.contains("symbolic link"), "{err}");
        assert!(
            err.contains(&format!("{} -> {}", link.display(), real.display())),
            "{err}"
        );
        assert!(err.contains("bind-mount"), "{err}");
        let err = format!("{:#}", refuse_linked_state_dir(&link).unwrap_err());
        assert!(err.contains("refusing to start"), "{err}");

        let after = std::fs::metadata(&real).unwrap();
        assert_eq!(
            after.mode() & 0o7777,
            0o755,
            "the target's mode is unchanged"
        );
        assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
        assert_eq!(
            std::fs::read_dir(&real).unwrap().count(),
            0,
            "nothing created in it"
        );

        // a dangling link too: never created through
        let dangling = t.path().join("dangling");
        std::os::unix::fs::symlink(t.path().join("nowhere"), &dangling).unwrap();
        assert!(ensure_state_dir(&dangling).is_err());
        assert!(!t.path().join("nowhere").exists());
        // the descriptor-level open refuses a link on its own as well
        let (uid, gid) = ids();
        let err = format!("{:#}", ensure_own_dir(&link, 0o700, uid, gid).unwrap_err());
        assert!(err.contains("does not follow a symbolic link"), "{err}");
        assert_eq!(std::fs::metadata(&real).unwrap().mode() & 0o7777, 0o755);
    }

    /// External audit ATP-007: non-regression — a real directory still
    /// gets its mode repaired (on the descriptor), a missing one is
    /// created, and the metadata returned is the directory's own.
    #[test]
    fn state_dir_mode_and_owner_still_repaired() {
        let t = TempDir::new().unwrap();
        let (uid, gid) = ids();
        let dir = t.path().join("state");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let meta = ensure_own_dir(&dir, 0o700, uid, gid).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o700);
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o7777, 0o700);
        assert_eq!(meta.ino(), std::fs::symlink_metadata(&dir).unwrap().ino());
        assert_eq!((meta.uid(), meta.gid()), (uid, gid));

        let fresh = t.path().join("fresh/state");
        let meta = ensure_own_dir(&fresh, 0o700, uid, gid).unwrap();
        assert!(meta.is_dir());
        assert_eq!(std::fs::metadata(&fresh).unwrap().mode() & 0o7777, 0o700);
        // a real directory passes the link check, and so does a missing one
        refuse_linked_state_dir(&dir).unwrap();
        refuse_linked_state_dir(&t.path().join("absent")).unwrap();
        let file = t.path().join("file");
        std::fs::write(&file, "x").unwrap();
        assert!(
            refuse_linked_state_dir(&file).is_err(),
            "a file is not a state dir"
        );
    }

    /// External audit ATP-007: a link at the quarantine directory, the
    /// vault, a chain sub-directory or a chain log is refused; the vault is
    /// not created through one.
    #[test]
    fn quarantine_link_is_refused() {
        let t = TempDir::new().unwrap();
        let elsewhere = t.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let state = t.path().join("state");
        std::fs::create_dir(&state).unwrap();
        std::os::unix::fs::symlink(&elsewhere, state.join("quarantine")).unwrap();
        let err = format!("{:#}", refuse_linked_state_dir(&state).unwrap_err());
        assert!(err.contains("quarantine ->"), "{err}");
        let err = format!("{:#}", ensure_quarantine_dirs(&state).unwrap_err());
        assert!(err.contains("not created through a link"), "{err}");
        assert!(
            !elsewhere.join("vault").exists(),
            "no vault in the link's target"
        );

        for entry in [
            "detections",
            "fim_baseline.jsonl",
            "detections/detections.jsonl",
        ] {
            let st = t.path().join(format!("s-{}", entry.replace('/', "-")));
            std::fs::create_dir(&st).unwrap();
            if let Some(parent) = Path::new(entry)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
            {
                std::fs::create_dir(st.join(parent)).unwrap();
            }
            let target = elsewhere.join(format!("t-{}", entry.replace('/', "-")));
            std::fs::write(&target, "x").unwrap();
            std::os::unix::fs::symlink(&target, st.join(entry)).unwrap();
            let err = format!("{:#}", refuse_linked_state_dir(&st).unwrap_err());
            assert!(err.contains(&format!("{entry} ->")), "{entry}: {err}");
        }

        // the vault is still made in a real state directory
        let ok = t.path().join("ok");
        std::fs::create_dir(&ok).unwrap();
        ensure_quarantine_dirs(&ok).unwrap();
        assert!(ok.join("quarantine/vault").is_dir());
        refuse_linked_state_dir(&ok).unwrap();
    }

    /// External audit ATP-007: an entry of the agent's directories is keyed
    /// by the link itself, never by the file a link points to.
    #[test]
    fn a_linked_own_file_is_keyed_by_the_link_not_its_target() {
        let t = TempDir::new().unwrap();
        let target = t.path().join("passwd");
        std::fs::write(&target, "root:x:0:0::/root:/bin/sh\n").unwrap();
        let link = t.path().join("fim_baseline.jsonl");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let meta = own_entry_meta(&link).unwrap();
        assert!(meta.file_type().is_symlink());
        assert_ne!(meta.ino(), std::fs::metadata(&target).unwrap().ino());
        assert_eq!(meta.ino(), std::fs::symlink_metadata(&link).unwrap().ino());
    }

    /// External audit ATP-016: the hooks a bootstrap failure leaves out.
    #[test]
    fn a_bootstrap_failure_loses_every_fs_hook() {
        let h = hooks_lost_to_bootstrap_failure(|h| Some(h == "inode_set_acl"), "x".into());
        assert_eq!(h.deny_failures.len(), LSM_PROGRAMS.len() + 1);
        assert_eq!(h.optional_present, 1);
        assert_eq!(h.observe_failures.len(), MODULE_LOAD_PROGRAMS.len());
        assert_eq!(
            h.infra_failures,
            vec![("filesystem::attach", "x".to_string())]
        );
    }

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

    /// External audit TST-009: the exported deny set is the hooks
    /// `attach` counts — task_kill, ptrace, every `LSM_PROGRAMS` hook and
    /// the map guard — each once.
    #[test]
    fn deny_hooks_are_the_hooks_attach_counts() {
        use std::collections::BTreeSet;
        let exported: BTreeSet<&str> = super::super::DENY_HOOKS.iter().copied().collect();
        let mut attached: BTreeSet<&str> = LSM_PROGRAMS.iter().map(|(_, hook)| *hook).collect();
        attached.insert(super::super::TASK_KILL_HOOK);
        attached.insert(super::super::PTRACE_HOOK);
        attached.insert(super::super::bpf_defense::GUARD_HOOK);
        assert_eq!(exported, attached);
        assert_eq!(
            exported.len(),
            super::super::DENY_HOOKS.len(),
            "a hook listed twice"
        );
        assert_eq!(super::super::LSM_DENY_HOOKS_EXPECTED, 16);
        let optional: BTreeSet<&str> = OPTIONAL_LSM_PROGRAMS
            .iter()
            .map(|(_, hook)| *hook)
            .collect();
        let exported_optional: BTreeSet<&str> =
            super::super::OPTIONAL_DENY_HOOKS.iter().copied().collect();
        assert_eq!(exported_optional, optional);
    }

    // ── Tappa 8 A14 (B4) — /etc/northnarrow registration tests ─────

    /// A14 + C7 + N8 + Tappa 10.5 D1 test: `ETC_PROTECTED_FILES` is
    /// a stable, ordered list of the fifteen file basenames. The
    /// ordering matters for the operator-visible audit-log entries;
    /// anchor it explicitly. A14 originally specified four files;
    /// Tappa 9 C7 appended `fim-paths.v1` + `fim-paths.local`,
    /// Tappa 10 N8 appended the four `netflow-*-blocklist*` files,
    /// and Tappa 10.5 D1 appended the four comm-allowlist files —
    /// each later commit only APPENDS so existing positions stay
    /// stable for any audit-log reader that indexes by slot.
    /// External audit EVD-001: a read-denied file is write- and
    /// mutation-denied too, and they fit the kernel's slots.
    #[test]
    fn read_denied_files_are_write_denied_and_fit_the_slots() {
        for f in ETC_READ_DENY_FILES {
            assert!(ETC_WRITE_DENY_FILES.contains(f), "{f}");
            assert!(ETC_PROTECTED_FILES.contains(f), "{f}");
        }
        for f in ETC_WRITE_DENY_FILES {
            assert!(ETC_PROTECTED_FILES.contains(f), "{f}");
        }
        assert!(ETC_READ_DENY_FILES.len() <= READ_PROTECTED_SLOTS as usize);
        assert!(!ETC_READ_DENY_FILES.contains(&"agent.sig.pub"));
    }

    #[test]
    fn etc_protected_files_lists_the_design_files() {
        assert_eq!(
            ETC_PROTECTED_FILES,
            &[
                "admin.pub",
                "agent_id",
                "audit.log",
                "agent.sig.key",
                "fim-paths.v1",
                "fim-paths.local",
                "netflow-blocklist.v1",
                "netflow-blocklist.local",
                "netflow-ja3-blocklist.v1",
                "netflow-ja3-blocklist.local",
                "process-comm-allowlist.v1",
                "process-comm-allowlist.local",
                "netflow-comm-allowlist.v1",
                "netflow-comm-allowlist.local",
                "install-manifest.json",
                // Tappa 10.8 — APPENDED: posture overlays + signature files.
                "mass-write-carveout.local",
                "escalation-allow.local",
                "fim-paths.local.sig",
                "netflow-blocklist.local.sig",
                "netflow-ja3-blocklist.local.sig",
                "process-comm-allowlist.local.sig",
                "netflow-comm-allowlist.local.sig",
                "mass-write-carveout.local.sig",
                "escalation-allow.local.sig",
                "combat-rules.v4",
                "combat-rules.v6",
                "combat-allow.cidrs",
                "combat-rules.v4.sig",
                "combat-rules.v6.sig",
                "combat-allow.cidrs.sig",
                "canary-readers.local",
                "canary-readers.local.sig",
                "agent.sig.pub",
                "chain_heads.json",
            ],
            "design §9 / commit A14 + Tappa 9 C7 + Tappa 10 N8 + \
             Tappa 10.5 D1 specify these files in this order"
        );
        assert_eq!(CONFIG_DIR, "/etc/northnarrow");
        // Lab PR 160: the head anchor lives next to the audit log.
        assert_eq!(
            crate::chain_anchor::DEFAULT_HEADS_PATH,
            format!("{CONFIG_DIR}/{}", crate::chain_anchor::HEADS_FILE_NAME)
        );
        assert!(ETC_WRITE_DENY_FILES.contains(&crate::chain_anchor::HEADS_FILE_NAME));
    }

    /// External audit ATP-008 (with FIMR-001): every shipped `.v1` list is
    /// write-denied — only install.sh writes one, with the pins dropped.
    #[test]
    fn curated_v1_lists_are_write_denied() {
        for name in ETC_PROTECTED_FILES.iter().filter(|n| n.ends_with(".v1")) {
            assert!(
                ETC_WRITE_DENY_FILES.contains(name),
                "{name} must be write-denied"
            );
        }
    }

    /// Tappa 10.5 D1 test: `ETC_PROTECTED_FILES` includes the four
    /// comm-allowlist files — `process-comm-allowlist.{v1,local}`
    /// (process rule exemptions) and `netflow-comm-allowlist.{v1,local}`
    /// (net rule trusted-actor set). Mirrors the focused N8
    /// `etc_protected_files_includes_net_blocklists` test — calls
    /// out the D1 widening intent so a future refactor that drops an
    /// entry fails fast even if it pacifies the exhaustive list above.
    #[test]
    fn etc_protected_files_includes_comm_allowlists() {
        for name in [
            "process-comm-allowlist.v1",
            "process-comm-allowlist.local",
            "netflow-comm-allowlist.v1",
            "netflow-comm-allowlist.local",
        ] {
            assert!(
                ETC_PROTECTED_FILES.contains(&name),
                "{name} must be in ETC_PROTECTED_FILES (Tappa 10.5 D1 LSM widening)"
            );
        }
    }

    /// N8 test: `ETC_PROTECTED_FILES` includes the four Tappa 10
    /// netflow blocklist files — `netflow-blocklist.v1` + its
    /// `.local` overlay (NN-L-NET-001 IP / CIDR set) and
    /// `netflow-ja3-blocklist.v1` + its `.local` overlay
    /// (NN-L-NET-003 JA3 fingerprint set). Focused test alongside
    /// the exhaustive `etc_protected_files_lists_the_design_files`
    /// — calls out the N8 widening intent and fails fast if a
    /// future refactor drops one of the four entries without
    /// touching the exhaustive list (e.g. a rename that leaves
    /// the exhaustive list happy but breaks the blocklist tamper
    /// invariant).
    #[test]
    fn etc_protected_files_includes_net_blocklists() {
        for name in [
            "netflow-blocklist.v1",
            "netflow-blocklist.local",
            "netflow-ja3-blocklist.v1",
            "netflow-ja3-blocklist.local",
        ] {
            assert!(
                ETC_PROTECTED_FILES.contains(&name),
                "{name} must be in ETC_PROTECTED_FILES (Tappa 10 N8 LSM widening)"
            );
        }
    }

    /// C7 + K7 + N8 + N9 test: `STATE_PROTECTED_FILES` lists the
    /// six /var/lib/northnarrow/ chain files that PROTECTED_INODES
    /// must cover. C7 shipped the two FIM logs; Tappa 9.5 K7
    /// APPENDED the two canary chain files; Tappa 10 N8 APPENDED
    /// `netflow.jsonl`; Tappa 10 N9 APPENDS
    /// `netflow_listeners.jsonl` at the END so existing entries'
    /// positions stay stable for any audit-log reader that indexes
    /// by slot.
    #[test]
    fn state_protected_files_lists_the_six_state_logs() {
        assert_eq!(
            STATE_PROTECTED_FILES,
            &[
                "fim_baseline.jsonl",
                "fim_drift.jsonl",
                "canaries.jsonl",
                "canary_access.jsonl",
                "netflow.jsonl",
                "netflow_listeners.jsonl",
            ],
            "design §6.4 + Tappa 9.5 §9 + Tappa 10 §6.4 / §10 \
             specify these six files in this order"
        );
        assert_eq!(STATE_DIR, "/var/lib/northnarrow");
    }

    /// N9 test: `STATE_PROTECTED_FILES` includes
    /// `netflow_listeners.jsonl`. Mirrors the focused
    /// `etc_protected_files_includes_net_blocklists` test — calls
    /// out the N9 widening intent so a future refactor that drops
    /// the entry fails fast even if it pacifies the exhaustive
    /// list assertion above.
    #[test]
    fn state_protected_files_includes_netflow_listeners_log() {
        assert!(
            STATE_PROTECTED_FILES.contains(&"netflow_listeners.jsonl"),
            "netflow_listeners.jsonl must be in STATE_PROTECTED_FILES \
             (Tappa 10 N9 LSM widening)"
        );
    }

    /// K7 test: `bootstrap_canary_log` creates a zero-byte file
    /// at mode 0600 (external audit EVD-019) when missing — mirrors the
    /// `bootstrap_fim_log` + `bootstrap_audit_log` contract so
    /// the LSM-protected layout invariants hold uniformly across
    /// all four /var/lib/northnarrow/ chain files.
    #[test]
    fn bootstrap_canary_log_creates_zero_byte_file_if_missing() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("canaries.jsonl");
        assert!(!log_path.exists());
        bootstrap_canary_log(&log_path).expect("bootstrap missing canary log");
        assert!(log_path.exists());
        let meta = std::fs::metadata(&log_path).unwrap();
        assert_eq!(meta.len(), 0);
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    /// K7 test: `bootstrap_canary_log` is idempotent — a second
    /// call on an existing file is a no-op and does NOT truncate
    /// (defends against the same defensive-bootstrap-on-every-
    /// boot foot-gun that bootstrap_fim_log + bootstrap_audit_log
    /// guard against; we MUST NOT silently erase a prior canary
    /// registry chain on agent restart).
    #[test]
    fn bootstrap_canary_log_is_idempotent_and_preserves_content() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("canary_access.jsonl");
        bootstrap_canary_log(&log_path).expect("first bootstrap");
        std::fs::write(&log_path, b"existing canary access line\n").unwrap();
        bootstrap_canary_log(&log_path).expect("second bootstrap");
        let body = std::fs::read_to_string(&log_path).unwrap();
        assert_eq!(
            body, "existing canary access line\n",
            "second bootstrap must NOT truncate"
        );
    }

    /// K7 test: `ETC_PROTECTED_TEMPLATES` lists the five canary
    /// content templates the K4 renderer reads from
    /// `/etc/northnarrow/canary-templates/`. Tamper here would
    /// silently widen / narrow what bytes get written onto the
    /// host at `canary deploy` time, so they must be in
    /// PROTECTED_INODES. Order anchored for audit-log stability,
    /// matching the same convention as ETC_PROTECTED_FILES +
    /// STATE_PROTECTED_FILES.
    #[test]
    fn etc_protected_templates_lists_the_five_template_files() {
        assert_eq!(
            ETC_PROTECTED_TEMPLATES,
            &[
                "aws.tmpl",
                "azure.tmpl",
                "docker.tmpl",
                "gcp.tmpl",
                "generic.tmpl",
            ],
            "design §9 + Tappa 9.5 K7 specify these five .tmpl basenames \
             (the K4 canary template families) in alphabetical order"
        );
        assert_eq!(CANARY_TEMPLATES_SUBDIR, "canary-templates");
    }

    /// N8 test: `bootstrap_netflow_log` creates a zero-byte file
    /// at mode 0600 (external audit EVD-019) when missing — mirrors the
    /// `bootstrap_fim_log` + `bootstrap_canary_log` contract so
    /// the LSM-protected layout invariants hold uniformly across
    /// all five /var/lib/northnarrow/ chain files.
    #[test]
    fn bootstrap_netflow_log_creates_zero_byte_file_if_missing() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("netflow.jsonl");
        assert!(!log_path.exists());
        bootstrap_netflow_log(&log_path).expect("bootstrap missing netflow log");
        assert!(log_path.exists());
        let meta = std::fs::metadata(&log_path).unwrap();
        assert_eq!(meta.len(), 0);
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    /// N8 test: `bootstrap_netflow_log` is idempotent — a second
    /// call on an existing file is a no-op and does NOT truncate
    /// (defends against the same defensive-bootstrap-on-every-
    /// boot foot-gun that bootstrap_fim_log + bootstrap_canary_log
    /// guard against; we MUST NOT silently erase a prior NetFlow
    /// audit chain on agent restart).
    #[test]
    fn bootstrap_netflow_log_is_idempotent_and_preserves_content() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("netflow.jsonl");
        bootstrap_netflow_log(&log_path).expect("first bootstrap");
        std::fs::write(&log_path, b"existing chained netflow line\n").unwrap();
        bootstrap_netflow_log(&log_path).expect("second bootstrap");
        let body = std::fs::read_to_string(&log_path).unwrap();
        assert_eq!(
            body, "existing chained netflow line\n",
            "second bootstrap must NOT truncate"
        );
    }

    /// N9 test: `bootstrap_netflow_listeners_log` creates a
    /// zero-byte file at mode 0600 (EVD-019) when missing. Same shape as
    /// the N8 bootstrap_netflow_log invariant for the sibling
    /// listeners chain.
    #[test]
    fn bootstrap_netflow_listeners_log_creates_zero_byte_file_if_missing() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("netflow_listeners.jsonl");
        assert!(!log_path.exists());
        bootstrap_netflow_listeners_log(&log_path)
            .expect("bootstrap missing netflow_listeners log");
        assert!(log_path.exists());
        let meta = std::fs::metadata(&log_path).unwrap();
        assert_eq!(meta.len(), 0);
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    /// N9 test: `bootstrap_netflow_listeners_log` is idempotent —
    /// a second call preserves prior content (no truncation).
    /// Defends the same "MUST NOT silently erase a prior chain
    /// on restart" invariant as bootstrap_netflow_log.
    #[test]
    fn bootstrap_netflow_listeners_log_is_idempotent_and_preserves_content() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("netflow_listeners.jsonl");
        bootstrap_netflow_listeners_log(&log_path).expect("first bootstrap");
        std::fs::write(&log_path, b"existing chained listeners line\n").unwrap();
        bootstrap_netflow_listeners_log(&log_path).expect("second bootstrap");
        let body = std::fs::read_to_string(&log_path).unwrap();
        assert_eq!(
            body, "existing chained listeners line\n",
            "second bootstrap must NOT truncate"
        );
    }

    /// C7 test: `bootstrap_fim_log` creates a zero-byte file at
    /// mode 0600 (external audit EVD-019) when missing — mirrors the `bootstrap_audit_log`
    /// contract so the LSM-protected layout invariants hold.
    #[test]
    fn bootstrap_fim_log_creates_zero_byte_file_if_missing() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("fim_baseline.jsonl");
        assert!(!log_path.exists());
        bootstrap_fim_log(&log_path).expect("bootstrap missing fim log");
        assert!(log_path.exists());
        let meta = std::fs::metadata(&log_path).unwrap();
        assert_eq!(meta.len(), 0);
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    /// C7 test: `bootstrap_fim_log` is idempotent — a second call
    /// on an existing file is a no-op and does NOT truncate
    /// (defends against a defensive bootstrap on every agent boot
    /// erasing prior baseline / drift chain entries).
    #[test]
    fn bootstrap_fim_log_is_idempotent_and_preserves_content() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("fim_drift.jsonl");
        bootstrap_fim_log(&log_path).expect("first bootstrap");
        std::fs::write(&log_path, b"existing chained drift line\n").unwrap();
        bootstrap_fim_log(&log_path).expect("second bootstrap");
        let body = std::fs::read_to_string(&log_path).unwrap();
        assert_eq!(
            body, "existing chained drift line\n",
            "second bootstrap must NOT truncate"
        );
    }

    /// External audit EVD-019 (NN-AUD-281): every evidence file the agent
    /// bootstraps is closed to other users — the state-dir chains to root
    /// (0600), the audit log and the head anchor in `/etc/northnarrow` to
    /// root and the file's group (0640).
    #[test]
    fn bootstrapped_evidence_files_are_closed_to_other_users() {
        let dir = TempDir::new().unwrap();
        let p = |n: &str| dir.path().join(n);
        bootstrap_detections_log(&p("detections/detections.jsonl")).unwrap();
        bootstrap_status_events_log(&p("detections/status_events.jsonl")).unwrap();
        bootstrap_fim_log(&p("fim_drift.jsonl")).unwrap();
        bootstrap_fim_log(&p("fim_baseline.jsonl")).unwrap();
        bootstrap_canary_log(&p("canaries.jsonl")).unwrap();
        bootstrap_canary_log(&p("canary_access.jsonl")).unwrap();
        bootstrap_netflow_log(&p("netflow.jsonl")).unwrap();
        bootstrap_netflow_listeners_log(&p("netflow_listeners.jsonl")).unwrap();
        bootstrap_audit_log(&p("etc/audit.log")).unwrap();
        bootstrap_chain_heads(&p("etc/chain_heads.json")).unwrap();
        let mode = |n: &str| std::fs::metadata(p(n)).unwrap().permissions().mode() & 0o7777;
        for n in [
            "detections/detections.jsonl",
            "detections/status_events.jsonl",
            "fim_drift.jsonl",
            "fim_baseline.jsonl",
            "canaries.jsonl",
            "canary_access.jsonl",
            "netflow.jsonl",
            "netflow_listeners.jsonl",
        ] {
            assert_eq!(mode(n), 0o600, "{n}: {:o}", mode(n));
        }
        for n in ["etc/audit.log", "etc/chain_heads.json"] {
            assert_eq!(mode(n), 0o640, "{n}: {:o}", mode(n));
        }
    }

    /// A14 test #2: `bootstrap_audit_log` creates a zero-byte
    /// file at the given path when it doesn't exist, with mode
    /// 0640: no longer world-readable (external audit EVD-019).
    #[test]
    fn bootstrap_audit_log_creates_zero_byte_file_if_missing() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.log");
        assert!(!log_path.exists());
        bootstrap_audit_log(&log_path).expect("bootstrap missing log");
        assert!(log_path.exists());
        let meta = std::fs::metadata(&log_path).unwrap();
        assert_eq!(meta.len(), 0);
        assert_eq!(meta.permissions().mode() & 0o777, 0o640);
    }

    /// A14 test #3: `bootstrap_audit_log` is idempotent — a
    /// second call on an existing file is a no-op and does NOT
    /// truncate (so prior audit entries survive an agent
    /// restart that calls bootstrap defensively at boot).
    #[test]
    fn bootstrap_audit_log_is_idempotent_and_preserves_content() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.log");
        bootstrap_audit_log(&log_path).expect("first bootstrap");
        std::fs::write(&log_path, b"existing entry line\n").unwrap();
        bootstrap_audit_log(&log_path).expect("second bootstrap");
        let body = std::fs::read_to_string(&log_path).unwrap();
        assert_eq!(
            body, "existing entry line\n",
            "second bootstrap must NOT truncate"
        );
    }

    /// A14 test #4: `bootstrap_audit_log` creates the parent
    /// directory at mode 0755 if it doesn't yet exist
    /// (handles a fresh /etc/northnarrow/ install where the
    /// operator hasn't created the directory manually).
    #[test]
    fn bootstrap_audit_log_creates_parent_dir_if_missing() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("etc/northnarrow");
        let log_path = nested.join("audit.log");
        assert!(!nested.exists());
        bootstrap_audit_log(&log_path).expect("bootstrap into missing dir");
        assert!(log_path.exists());
        let dir_meta = std::fs::metadata(&nested).unwrap();
        assert!(dir_meta.is_dir());
        assert_eq!(
            dir_meta.permissions().mode() & 0o777,
            0o755,
            "parent dir must be mode 0755 for design §6.5 layout"
        );
    }

    /// A14 test #5: the ETC_PROTECTED_FILES list does NOT
    /// include any path-traversal components. Defends against
    /// a future operator-editable config where one of these
    /// names becomes `../something` and the join with
    /// CONFIG_DIR escapes to an unrelated inode.
    #[test]
    fn state_protected_subdirs_are_bare_basenames() {
        for (sub, files) in STATE_PROTECTED_SUBDIRS {
            assert!(!sub.contains('/') && !sub.starts_with('.'), "{sub}");
            for f in files.iter() {
                assert!(!f.contains('/') && !f.starts_with('.'), "{f}");
            }
        }
        // The two Tappa 9.0 chains must stay covered.
        let (sub, files) = STATE_PROTECTED_SUBDIRS[0];
        assert_eq!(sub, "detections");
        assert!(files.contains(&"detections.jsonl") && files.contains(&"status_events.jsonl"));
    }

    #[test]
    fn etc_protected_files_have_no_path_traversal() {
        for name in ETC_PROTECTED_FILES {
            assert!(
                !name.contains('/'),
                "{name} must be a bare basename — no '/'"
            );
            assert!(
                !name.contains(".."),
                "{name} must not contain '..' (path traversal defence)"
            );
            assert!(
                !name.is_empty(),
                "ETC_PROTECTED_FILES entries must be non-empty"
            );
        }
    }

    /// A14 test #6: ETC_PROTECTED_FILES entries are unique —
    /// no duplicate names would silently register the same
    /// inode twice (idempotent in the map, but bumps the
    /// "registered N of total" log line incorrectly).
    #[test]
    fn etc_protected_files_are_unique() {
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for name in ETC_PROTECTED_FILES {
            assert!(
                seen.insert(name),
                "duplicate entry {name} in ETC_PROTECTED_FILES"
            );
        }
    }

    // ── Anti-tamper binary/unit pin — registration tests ───────────

    /// The binary/unit pin set is exactly these absolute paths: the
    /// agent + watchdog executables and their two systemd units in both
    /// install layouts (`install.sh`: `/usr/local/bin` +
    /// `/etc/systemd/system`; a package: `/usr/bin` +
    /// `/usr/lib/systemd/system`, review 26). Anchored explicitly so a
    /// refactor that drops or moves one fails fast — this is the
    /// authoritative "these are in PROTECTED_INODES" assertion for the
    /// binaries + units.
    #[test]
    fn binary_and_unit_paths_lists_both_layouts() {
        assert_eq!(
            BINARY_AND_UNIT_PATHS,
            &[
                "/usr/local/bin/northnarrow-agent",
                "/usr/local/bin/northnarrow-watchdog",
                "/etc/systemd/system/northnarrow-agent.service",
                "/etc/systemd/system/northnarrow-watchdog.service",
                "/usr/bin/northnarrow-agent",
                "/usr/bin/northnarrow-watchdog",
                "/usr/lib/systemd/system/northnarrow-agent.service",
                "/usr/lib/systemd/system/northnarrow-watchdog.service",
                "/etc/systemd/system/northnarrow-agent.service.d",
                "/etc/systemd/system/northnarrow-agent.service.d/10-debian-perf-paranoid.conf",
            ],
            "the agent + watchdog binaries and their two systemd units \
             are the anti-tamper binary/unit pin set"
        );
    }

    /// Unlike the basename consts, these entries are ABSOLUTE system
    /// paths (no parent-dir join), so the shape invariant is inverted
    /// from `etc_protected_files_have_no_path_traversal`: every entry
    /// must START with '/', be non-empty, and carry no `..` traversal
    /// component.
    #[test]
    fn binary_and_unit_paths_are_absolute_no_traversal() {
        for p in BINARY_AND_UNIT_PATHS {
            assert!(p.starts_with('/'), "{p} must be an absolute path");
            assert!(
                !p.is_empty(),
                "BINARY_AND_UNIT_PATHS entries must be non-empty"
            );
            assert!(
                !p.contains(".."),
                "{p} must not contain '..' (path-traversal defence)"
            );
        }
    }

    /// Duplicate entries would bump the "registered N of total" log
    /// line without adding protection (the map insert is idempotent).
    /// Mirrors `etc_protected_files_are_unique`.
    #[test]
    fn binary_and_unit_paths_are_unique() {
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for p in BINARY_AND_UNIT_PATHS {
            assert!(
                seen.insert(p),
                "duplicate entry {p} in BINARY_AND_UNIT_PATHS"
            );
        }
    }

    /// External audit EBPF-015: the deny set covers every way to add an
    /// entry to a directory (create, mkdir, mknod, symlink, link) and to
    /// change an extended attribute, each hook once; the ACL hooks of 6.2+
    /// are optional, and every pin name fits the BPF guard's name window.
    #[test]
    fn deny_set_covers_new_entries_and_xattrs() {
        let hooks: Vec<&str> = LSM_PROGRAMS.iter().map(|(_, h)| *h).collect();
        for h in [
            "inode_create",
            "inode_mkdir",
            "inode_mknod",
            "inode_symlink",
            "inode_link",
            "inode_setxattr",
            "inode_removexattr",
        ] {
            assert!(hooks.contains(&h), "no deny program on {h}");
        }
        let optional: Vec<&str> = OPTIONAL_LSM_PROGRAMS.iter().map(|(_, h)| *h).collect();
        assert_eq!(
            optional,
            ["inode_set_acl", "inode_remove_acl", "file_ioctl_compat"]
        );
        let mut programs = std::collections::HashSet::new();
        let mut seen = std::collections::HashSet::new();
        for (program, hook) in LSM_PROGRAMS.iter().chain(OPTIONAL_LSM_PROGRAMS) {
            assert!(programs.insert(*program), "program {program} listed twice");
            assert!(seen.insert(*hook), "hook {hook} listed twice");
            let (_, link) = antitamper_bpf::lsm_pin_paths(Path::new("/"), hook);
            let name = link.file_name().unwrap().len();
            assert!(name <= 32, "link pin name of {hook} too long for the guard");
        }
    }

    /// External audit EBPF-015: a hook the kernel does not have (its
    /// `bpf_lsm_<hook>` absent from the BTF) is told from a hook that
    /// failed to load — only the first lets an optional program be skipped.
    #[test]
    fn lsm_hook_absent_only_for_that_hook_missing_from_btf() {
        use aya::programs::ProgramError;
        let absent = anyhow::Error::from(ProgramError::Btf(aya::BtfError::UnknownBtfTypeName {
            type_name: "bpf_lsm_inode_set_acl".to_string(),
        }))
        .context("verifier rejected LSM program `protected_set_acl_deny`");
        assert!(lsm_hook_absent(&absent, "inode_set_acl"));
        assert!(!lsm_hook_absent(&absent, "inode_remove_acl"));
        let failed = anyhow::Error::from(ProgramError::Btf(aya::BtfError::UnknownBtfTypeName {
            type_name: "inode".to_string(),
        }))
        .context("verifier rejected LSM program `protected_set_acl_deny`");
        assert!(!lsm_hook_absent(&failed, "inode_set_acl"));
        let other = anyhow::anyhow!("attaching LSM program `protected_set_acl_deny`");
        assert!(!lsm_hook_absent(&other, "inode_set_acl"));
    }

    /// Lab PR 174: an optional deny hook is tried only where the boot's BTF
    /// resolution does not say it is absent; with the hook in the BTF any
    /// attach error is a failure (an expected deny hook missing), and only
    /// without a resolution does the loader's "no `bpf_lsm_<hook>`" mean
    /// absent.
    #[test]
    fn optional_hook_attach_follows_the_btf() {
        use aya::programs::ProgramError;
        let hook = "file_ioctl_compat";
        let absent_err = || {
            anyhow::Error::from(ProgramError::Btf(aya::BtfError::UnknownBtfTypeName {
                type_name: "bpf_lsm_file_ioctl_compat".to_string(),
            }))
            .context("verifier rejected LSM program `protected_ioctl_compat_deny`")
        };
        assert!(lsm_hook_absent(&absent_err(), hook));
        assert!(!lsm_hook_absent(&absent_err(), "file_ioctl"));

        let skipped = attach_optional(hook, Some(false), || panic!("tried a hook the BTF lacks"));
        assert_eq!(skipped, OptionalHook::Absent);
        assert!(!skipped.expected());

        let attached = attach_optional(hook, Some(true), || Ok(()));
        assert_eq!(attached, OptionalHook::Attached);
        assert!(attached.expected());

        let failed = attach_optional(hook, Some(true), || {
            Err(anyhow::anyhow!(
                "verifier rejected LSM program `protected_ioctl_compat_deny`"
            ))
        });
        assert!(matches!(&failed, OptionalHook::Failed(e) if e.contains("verifier rejected")));
        assert!(failed.expected());
        // the BTF has the hook: the loader's "absent" is a failure, not a skip
        assert!(matches!(
            attach_optional(hook, Some(true), || Err(absent_err())),
            OptionalHook::Failed(_)
        ));

        // no resolution: the loader's lookup decides
        assert_eq!(
            attach_optional(hook, None, || Err(absent_err())),
            OptionalHook::Absent
        );
        assert!(matches!(
            attach_optional(hook, None, || Err(anyhow::anyhow!("attach failed"))),
            OptionalHook::Failed(_)
        ));
        assert_eq!(
            attach_optional(hook, None, || Ok(())),
            OptionalHook::Attached
        );
    }

    /// External audit EBPF-015: the agent's directories refuse new
    /// entries; the files, and the host's shared directories, do not carry
    /// the flag (a NOCREATE `/usr/local/bin` would refuse every install).
    #[test]
    fn only_the_agents_own_directories_refuse_new_entries() {
        assert_eq!(PROTECTED_DIR_FLAGS, FS_PROTECT_MUTATE | FS_PROTECT_NOCREATE);
        for d in NOCREATE_UNIT_DIRS {
            assert!(BINARY_AND_UNIT_PATHS.contains(d), "{d}");
            assert!(d.contains("northnarrow"), "{d} is not the agent's own");
            assert_ne!(binary_or_unit_flags(Path::new(d)) & FS_PROTECT_NOCREATE, 0);
        }
        for p in BINARY_AND_UNIT_PATHS {
            let f = binary_or_unit_flags(Path::new(p));
            assert_eq!(
                f & (FS_PROTECT_MUTATE | FS_PROTECT_WRITE),
                FS_PROTECT_MUTATE | FS_PROTECT_WRITE
            );
            if !NOCREATE_UNIT_DIRS.contains(p) {
                assert_eq!(f & FS_PROTECT_NOCREATE, 0, "{p}");
            }
        }
        for shared in [
            "/usr/local/bin",
            "/usr/bin",
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/etc",
        ] {
            assert_eq!(
                binary_or_unit_flags(Path::new(shared)) & FS_PROTECT_NOCREATE,
                0
            );
        }
    }

    /// `resolve_protected_paths` resolves every path that exists to a
    /// `(path, InodeKey)` whose key matches the file's real
    /// `(kernel-dev, ino)`. Exercised through a tempdir so it stays
    /// hermetic (the real `/usr/local/bin` paths may or may not exist
    /// on a CI box). This is the "all four register" case.
    #[test]
    fn resolve_protected_paths_resolves_every_present_file() {
        let dir = TempDir::new().unwrap();
        let mut paths_owned = Vec::new();
        for name in ["agent-bin", "watchdog-bin", "a.service", "b.service"] {
            let p = dir.path().join(name);
            std::fs::write(&p, b"x").unwrap();
            paths_owned.push(p.to_str().unwrap().to_string());
        }
        let refs: Vec<&str> = paths_owned.iter().map(String::as_str).collect();

        let resolved = resolve_protected_paths(&refs);

        assert_eq!(resolved.len(), 4, "all four present files must resolve");
        for (path, key) in &resolved {
            let meta = std::fs::metadata(path).unwrap();
            assert_eq!(key.dev, stat_dev_to_kernel_dev(meta.dev()));
            assert_eq!(key.ino, meta.ino());
        }
    }

    /// A missing path is skipped with a warn — NOT fatal: the resolver
    /// returns the present entries and silently drops the absent one
    /// (a host without the watchdog binary still arms the paths it
    /// has). This is the resolution-layer half of "N registered,
    /// missing skipped"; the actual `register_inode` map insert needs
    /// a live `Ebpf` and is covered by the privileged e2e suite.
    #[test]
    fn resolve_protected_paths_skips_missing_not_fatal() {
        let dir = TempDir::new().unwrap();
        let present = dir.path().join("present-bin");
        std::fs::write(&present, b"x").unwrap();
        let missing = dir.path().join("not-installed");
        let present_s = present.to_str().unwrap().to_string();
        let missing_s = missing.to_str().unwrap().to_string();

        let resolved = resolve_protected_paths(&[present_s.as_str(), missing_s.as_str()]);

        assert_eq!(
            resolved.len(),
            1,
            "missing path skipped, present kept — not fatal"
        );
        assert_eq!(
            resolved[0].0, present,
            "the surviving entry is the present file"
        );
    }
}
