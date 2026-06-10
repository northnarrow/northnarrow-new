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
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use aya::{
    maps::{HashMap as AyaHashMap, Map as AyaMap, MapData},
    Btf, Ebpf,
};
use common::wire::{InodeKey, FS_PROTECT_MUTATE, FS_PROTECT_WRITE};

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

/// Config directory holding admin-controlled secrets + agent
/// identity files. Tappa 8 A14 (B4) widens PROTECTED_INODES to
/// cover this directory's contents so an attacker with root
/// can't tamper with `admin.pub` / `agent_id` / `audit.log` /
/// `agent.sig.key` between agent restarts. The directory itself
/// is not registered (operators legitimately add new files
/// here — e.g., dropping a fresh pubkey for `rotate-keys add`);
/// only the individual files are.
pub const CONFIG_DIR: &str = "/etc/northnarrow";

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
];

/// at-authz-1: the subset of [`ETC_PROTECTED_FILES`] that is also
/// WRITE-open-denied (`FS_PROTECT_WRITE`), not just mutation-denied.
/// These are the secret/integrity identity files written ONLY by the
/// agent at runtime (admin.pub via the rename-based rotate-keys path;
/// agent_id / agent.sig.key at bootstrap; audit.log via the append-only
/// chain), so any runtime non-agent write is unambiguous tamper. The
/// remaining [`ETC_PROTECTED_FILES`] are operator-tunable (allowlists /
/// blocklists / fim-paths overlays) and stay MUTATE-only — write-denying
/// them would turn a routine live edit into an enforce-mode COMBAT
/// (NIC-isolation) trip. Every entry MUST also appear in
/// [`ETC_PROTECTED_FILES`].
pub const ETC_WRITE_DENY_FILES: &[&str] = &["admin.pub", "agent_id", "audit.log", "agent.sig.key"];

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
/// directory), these are ABSOLUTE paths — the set spans
/// `/usr/local/bin` and `/etc/systemd/system`, so there is no single
/// parent dir to join. The two `.service` files are the same units
/// the in-flight FIM-009 trusted-installer override is built to
/// govern; the two binaries are the new coverage.
///
/// eBPF-only, NO `chattr +i`: the `+i` belt-and-suspenders stays the
/// state dir's. These use the file-LSM mechanism for consistency with
/// the /etc identity files — and so a signed self-upgrade can replace
/// them during an armed `FS_PROTECT_OVERRIDE` window (a global deny
/// suspension) without first having to clear a per-inode immutable
/// bit.
pub const BINARY_AND_UNIT_PATHS: &[&str] = &[
    "/usr/local/bin/northnarrow-agent",
    "/usr/local/bin/northnarrow-watchdog",
    "/etc/systemd/system/northnarrow-agent.service",
    "/etc/systemd/system/northnarrow-watchdog.service",
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

/// The six LSM deny programs from `agent-ebpf/src/inode_protect.rs`.
/// First field is the program name in the ELF, second is the LSM
/// hook name the kernel exposes as `bpf_lsm_<hook>` in vmlinux BTF.
/// `protected_open_deny` (at-authz-1) is the `file_open` FMODE_WRITE
/// deny that closes the write-open gap on `FS_PROTECT_WRITE` inodes.
const LSM_PROGRAMS: &[(&str, &str)] = &[
    ("inode_unlink", "inode_unlink"),
    ("inode_rmdir", "inode_rmdir"),
    ("inode_rename", "inode_rename"),
    ("inode_setattr", "inode_setattr"),
    ("file_ioctl", "file_ioctl"),
    ("protected_open_deny", "file_open"),
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

pub(crate) fn attach(ebpf: &mut Ebpf, btf: &Btf, pin_root: Option<&Path>) -> Result<()> {
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
    // The state dir is a directory — a write-open (FMODE_WRITE) of a dir
    // never happens (open returns EISDIR), so MUTATE-only is the complete
    // and correct mask for the dir inode itself; the WRITE bit lives on
    // the chain-log FILES inside it (register_state_files).
    register_inode(ebpf, &key, FS_PROTECT_MUTATE)?;
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
    // FS_PROTECT_OVERRIDE window.
    if let Err(e) = register_binary_and_units(ebpf) {
        warn!(
            error = %e,
            "anti-tamper FS: agent binary/unit registration failed — \
             agent executable + service files defended only by POSIX perms this boot"
        );
    }

    // Step 4: attach the five inode_protect deny hooks — the
    // FS_PROTECT_EVENTS producers. BUG-024: these MUST re-attach FRESH
    // every boot (binding to this boot's fresh, process-local ring) rather
    // than reuse the prior boot's pinned link (which kept producing into the
    // old pinned ring and desynced the new consumer → ~1.6k/sec stale-denial
    // replay that DoS'd observability). `reattach_fresh` attaches this boot's
    // program BEFORE purging the old pin, so a deny program is attached at
    // every instant (zero-window). task_kill/ptrace (anti_tamper/mod.rs) keep
    // the pinned-reuse path — they emit no ring, so they don't desync.
    let mut deny_hooks_attached: usize = 0;
    for (program, hook) in LSM_PROGRAMS {
        match super::reattach_fresh(ebpf, program, hook, btf, pin_root) {
            Ok(()) => deny_hooks_attached += 1,
            Err(e) => warn!(
                program, hook, error = %e,
                "anti-tamper FS: LSM hook attach FAILED"
            ),
        }
    }
    // at-authz-1 verify-item 3: a machine-detectable attach-health signal.
    // The attach path stays warn-and-continue (a benign failure must not
    // self-DoS — refuse-to-start is rejected; holistic fail-closed is
    // ebpf-lsm-1), but emit one structured line carrying the attached vs
    // expected count so monitoring can alert when `deny_hooks_attached <
    // deny_hooks_expected` (a silently-absent deny hook = at-authz-1 /
    // mutation protection partially off while the agent reports healthy).
    let deny_hooks_expected = LSM_PROGRAMS.len();
    if deny_hooks_attached == deny_hooks_expected {
        info!(
            deny_hooks_attached,
            deny_hooks_expected,
            "anti-tamper FS: all inode_protect deny hooks attached"
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
        }
    }

    Ok(())
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
    for name in ETC_PROTECTED_FILES {
        let path = etc_dir.join(name);
        let meta = match std::fs::metadata(&path) {
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
        let flags = FS_PROTECT_MUTATE
            | if ETC_WRITE_DENY_FILES.contains(name) {
                FS_PROTECT_WRITE
            } else {
                0
            };
        register_inode(ebpf, &key, flags)
            .with_context(|| format!("registering {} in {PROTECTED_INODES_MAP}", path.display()))?;
        info!(
            path = %path.display(),
            kernel_dev = key.dev,
            ino = key.ino,
            write_deny = flags & FS_PROTECT_WRITE != 0,
            "anti-tamper FS: /etc/northnarrow file registered in {PROTECTED_INODES_MAP}"
        );
        registered += 1;
    }
    info!(
        etc_dir = %etc_dir.display(),
        registered,
        total = ETC_PROTECTED_FILES.len(),
        "anti-tamper FS: /etc/northnarrow file registration complete"
    );
    Ok(registered)
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
        let meta = match std::fs::metadata(&path) {
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
        info!(
            path = %path.display(),
            kernel_dev = key.dev,
            ino = key.ino,
            "anti-tamper FS: /var/lib/northnarrow FIM log registered in {PROTECTED_INODES_MAP}"
        );
        registered += 1;
    }
    info!(
        state_dir = %state_dir.display(),
        registered,
        total = STATE_PROTECTED_FILES.len(),
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
        let meta = match std::fs::metadata(&path) {
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
        let meta = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                warn!(
                    path = %path.display(),
                    "anti-tamper FS: skip register_binary_and_units entry — file missing \
                     (will be unprotected until next agent restart with the file present)"
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
pub(crate) fn register_binary_and_units(ebpf: &mut Ebpf) -> Result<usize> {
    let mut registered = 0usize;
    for (path, key) in resolve_protected_paths(BINARY_AND_UNIT_PATHS) {
        // at-authz-1: the agent/watchdog images + units are agent-written
        // (signed self-upgrade, exempt via FS_PROTECT_OVERRIDE) — WRITE+MUTATE.
        register_inode(ebpf, &key, FS_PROTECT_MUTATE | FS_PROTECT_WRITE)
            .with_context(|| format!("registering {} in {PROTECTED_INODES_MAP}", path.display()))?;
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
    // 0644: world-readable for operator `cat`-inspection, only
    // root + the agent's user can write (LSM-enforced append-only
    // applies via PROTECTED_INODES + PROTECTED_PIDS exemption,
    // same as the FIM logs).
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o644)
        .open(canary_log_path)
        .with_context(|| format!("creating canary log {}", canary_log_path.display()))?;
    info!(
        path = %canary_log_path.display(),
        "anti-tamper FS: canary log bootstrapped (zero-byte placeholder for PROTECTED_INODES)"
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
        .mode(0o644)
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
    // 0644: world-readable for operator `cat`-inspection, only
    // root + the agent's user can write (LSM-enforced append-only
    // applies via PROTECTED_INODES + PROTECTED_PIDS exemption,
    // same as the FIM + canary logs).
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o644)
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
    // 0644: world-readable for operator `cat`-inspection, only
    // root + the agent's user can write (LSM-enforced append-only
    // applies via PROTECTED_INODES + PROTECTED_PIDS exemption).
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o644)
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
/// missing, then a zero-byte 0644 active file. Idempotent: a present
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
    // 0644: world-readable for operator inspection, agent-writable
    // (append-only enforced via PROTECTED_INODES + the agent's PID
    // exemption) — same envelope as the FIM drift log.
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o644)
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
/// inside the same `detections/` dir, with the same zero-byte 0644
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
    // 0644: world-readable for operator inspection, agent-writable.
    // (NOT yet PROTECTED_INODES-registered — see the fn doc-comment;
    // same gap as the sibling detection log.)
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o644)
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
    // 0644 matches the rest of /etc/northnarrow/ layout (design
    // §6.5: world-readable, root-only writable + LSM-enforced
    // append-only). Empty file body — first append writes the
    // genesis entry.
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o644)
        .open(audit_log_path)
        .with_context(|| format!("creating audit log {}", audit_log_path.display()))?;
    info!(
        path = %audit_log_path.display(),
        "anti-tamper FS: audit log bootstrapped (zero-byte placeholder for PROTECTED_INODES)"
    );
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

/// Insert `key` into `PROTECTED_INODES` with the at-authz-1 `flags`
/// mask (`FS_PROTECT_MUTATE` and/or `FS_PROTECT_WRITE`). The map value
/// records which deny classes apply to this inode so the eBPF
/// `deny_if_protected` can be op-aware (the write-open deny covers only
/// the `FS_PROTECT_WRITE` subset). An existing entry is overwritten.
fn register_inode(ebpf: &mut Ebpf, key: &InodeKey, flags: u8) -> Result<()> {
    let map = ebpf
        .map_mut(PROTECTED_INODES_MAP)
        .ok_or_else(|| anyhow!("map {PROTECTED_INODES_MAP} missing from eBPF object"))?;
    let mut map: AyaHashMap<&mut MapData, AyaInodeKey, u8> = AyaHashMap::try_from(map)
        .with_context(|| format!("{PROTECTED_INODES_MAP} is not a HashMap<InodeKey, u8>"))?;
    map.insert(AyaInodeKey(*key), flags, 0).with_context(|| {
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
        self.map.insert(AyaInodeKey(key), flags, 0).with_context(|| {
            format!(
                "registering (dev={}, ino={}) in {PROTECTED_INODES_MAP}",
                key.dev, key.ino
            )
        })
    }

    /// Drop a stale inode key (best-effort at the call sites that use it):
    /// after a rename-replace the old inode is freed and its dev/ino could
    /// later be reused by an unrelated, non-protected file.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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

    // ── Tappa 8 A14 (B4) — /etc/northnarrow registration tests ─────

    /// A14 + C7 + N8 + Tappa 10.5 D1 test: `ETC_PROTECTED_FILES` is
    /// a stable, ordered list of the fourteen file basenames. The
    /// ordering matters for the operator-visible audit-log entries;
    /// anchor it explicitly. A14 originally specified four files;
    /// Tappa 9 C7 appended `fim-paths.v1` + `fim-paths.local`,
    /// Tappa 10 N8 appended the four `netflow-*-blocklist*` files,
    /// and Tappa 10.5 D1 appended the four comm-allowlist files —
    /// each later commit only APPENDS so existing positions stay
    /// stable for any audit-log reader that indexes by slot.
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
            ],
            "design §9 / commit A14 + Tappa 9 C7 + Tappa 10 N8 + \
             Tappa 10.5 D1 specify these files in this order"
        );
        assert_eq!(CONFIG_DIR, "/etc/northnarrow");
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
    /// at mode 0644 when missing — mirrors the
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
        assert_eq!(meta.permissions().mode() & 0o777, 0o644);
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
    /// at mode 0644 when missing — mirrors the
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
        assert_eq!(meta.permissions().mode() & 0o777, 0o644);
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
    /// zero-byte file at mode 0644 when missing. Same shape as
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
        assert_eq!(meta.permissions().mode() & 0o777, 0o644);
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
    /// mode 0644 when missing — mirrors the `bootstrap_audit_log`
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
        assert_eq!(meta.permissions().mode() & 0o777, 0o644);
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

    /// A14 test #2: `bootstrap_audit_log` creates a zero-byte
    /// file at the given path when it doesn't exist, with mode
    /// 0644 so the LSM-protected world-readable contract holds.
    #[test]
    fn bootstrap_audit_log_creates_zero_byte_file_if_missing() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.log");
        assert!(!log_path.exists());
        bootstrap_audit_log(&log_path).expect("bootstrap missing log");
        assert!(log_path.exists());
        let meta = std::fs::metadata(&log_path).unwrap();
        assert_eq!(meta.len(), 0);
        assert_eq!(meta.permissions().mode() & 0o777, 0o644);
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

    /// The binary/unit pin set is exactly the four absolute paths: the
    /// agent + watchdog executables under `/usr/local/bin` and their
    /// two systemd units under `/etc/systemd/system`. Anchored
    /// explicitly so a refactor that drops or moves one fails fast —
    /// this is the authoritative "these four are in PROTECTED_INODES"
    /// assertion for the binaries + units.
    #[test]
    fn binary_and_unit_paths_lists_the_four_targets() {
        assert_eq!(
            BINARY_AND_UNIT_PATHS,
            &[
                "/usr/local/bin/northnarrow-agent",
                "/usr/local/bin/northnarrow-watchdog",
                "/etc/systemd/system/northnarrow-agent.service",
                "/etc/systemd/system/northnarrow-watchdog.service",
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
