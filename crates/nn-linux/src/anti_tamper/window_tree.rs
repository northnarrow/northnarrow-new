//! Lot 2.3a (stage S2, the kernel side): the programs of the
//! trusted-installer window per process tree (`agent-ebpf/src/window_tree.rs`)
//! and what the kernel needs for a tree window (the design's section 8,
//! "Kernel manifest").
//!
//! [`attach`] loads and attaches the fourteen programs ([`PROGRAMS`]), each pinned
//! under its own name in the pin root (`prog_<program>`, `link_<program>`:
//! several share their hook with another program of the agent, and a deny
//! hook's pin is named by its hook), the fresh one attached before the prior
//! boot's pin goes. [`manifest_missing`] names what this kernel or this
//! start lacks for a tree window — a program not attached, a field of the
//! per-lift test the kernel does not have, a key file `INODE_EXT` does not
//! keep (lot 2.3a, the key files) — and a tree grant is refused
//! while it names anything: the window never falls back to host-wide.
//!
//! Not a deny hook of the start's count: without them no tree window opens
//! (a signed degradation); the host-wide grant, the flows' until lots 2.3b
//! and 2.4, does not need them.

use std::path::Path;
use std::sync::OnceLock;

use aya::maps::{Array, MapData};
use aya::programs::links::FdLink;
use aya::programs::{BtfTracePoint, Lsm};
use aya::{Btf, Ebpf};
use tracing::{info, warn};

/// How a program attaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Lsm,
    /// A BTF tracepoint.
    TpBtf,
}

/// The tree's programs: `(program, how, hook or tracepoint)`, in the order
/// a start attaches them — the removal first (an entry never outlives its
/// process), the judges, the guards, then the fork's two halves (a child
/// joins only once what judges it runs; lot 2.3a's review of #647: its
/// `task_alloc` half before the confirmation at `sched_process_fork`).
pub const PROGRAMS: [(&str, Kind, &str); 14] = [
    ("tree_exit", Kind::TpBtf, "sched_process_exit"),
    ("tree_task_free", Kind::Lsm, "task_free"),
    ("tree_bprm_check", Kind::Lsm, "bprm_check_security"),
    ("tree_bprm_commit", Kind::Lsm, "bprm_committed_creds"),
    ("tree_exec_env", Kind::TpBtf, "sched_process_exec"),
    ("tree_mmap_file", Kind::Lsm, "mmap_file"),
    ("tree_mprotect", Kind::Lsm, "file_mprotect"),
    ("tree_shmat", Kind::Lsm, "shm_shmat"),
    ("tree_ptrace", Kind::Lsm, "ptrace_access_check"),
    ("tree_fd_receive", Kind::Lsm, "file_receive"),
    // lot 2.3b (D5): a mount on or over the system code frozen against
    // outsiders (programs of their own beside the mount guard's stages)
    ("tree_frz_mount", Kind::Lsm, "sb_mount"),
    ("tree_frz_move", Kind::Lsm, "move_mount"),
    ("tree_task_alloc", Kind::Lsm, "task_alloc"),
    ("tree_fork", Kind::TpBtf, "sched_process_fork"),
];

/// The fields the kernel reads for the lift test and the tree's judges
/// (`common::btf_offsets`), each one a missing hook when this kernel does
/// not have it: no lift, and no tree window.
/// Lot 2.3a (the review of #647): the task's `__state` (the fork span's
/// `TASK_NEW` guard; its `real_parent` is a field every start needs), and
/// the vma's flags and file (the `mprotect` judge: without them every
/// executable `mprotect` would be judged anonymous) are among them.
pub const REQUIRED_FIELDS: [&str; 16] = [
    "TASK_STRUCT_START_BOOTTIME_OFFSET",
    "TASK_STRUCT_PTRACE_OFFSET",
    "TASK_STRUCT_SECCOMP_MODE_OFFSET",
    "TASK_STRUCT_CRED_OFFSET",
    "CRED_USER_NS_OFFSET",
    "USER_NAMESPACE_INUM_OFFSET",
    "TASK_STRUCT_NSPROXY_OFFSET",
    "NSPROXY_PID_NS_FOR_CHILDREN_OFFSET",
    "PID_NAMESPACE_INUM_OFFSET",
    "TASK_STRUCT_SIGNAL_OFFSET",
    "SIGNAL_STRUCT_LIVE_OFFSET",
    "MM_STRUCT_ENV_START_OFFSET",
    "MM_STRUCT_ENV_END_OFFSET",
    "TASK_STRUCT_STATE_OFFSET",
    "VM_AREA_STRUCT_VM_FLAGS_OFFSET",
    "VM_AREA_STRUCT_VM_FILE_OFFSET",
];

/// The pinned slot of the window the kernel closed
/// (`agent-ebpf/src/window_tree.rs`'s `TREE_CLOSED`).
pub const TREE_CLOSED_MAP_NAME: &str = "TREE_CLOSED";

/// What the start attached: `Ok` every program, `Err` the ones it could
/// not, with why. Unset before [`attach`] ran (no deny hook this boot).
static ATTACHED: OnceLock<Result<(), String>> = OnceLock::new();

/// The pin paths of program `name` in `root`.
pub fn pin_paths(root: &Path, name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    (
        root.join(format!("prog_{name}")),
        root.join(format!("link_{name}")),
    )
}

/// Attach the tree's programs (see the module), empty the kernel's closed
/// slot (a window an earlier agent opened is closed by this start — boot
/// zero), and record the outcome for [`manifest_missing`]. `Err` names the
/// programs not attached: the caller signs it as a degradation.
pub fn attach(ebpf: &mut Ebpf, btf: &Btf, pin_root: Option<&Path>) -> Result<(), String> {
    let zeroed = zero_closed(ebpf);
    let mut missing = Vec::new();
    for (name, kind, target) in PROGRAMS {
        if let Err(e) = attach_one(ebpf, btf, pin_root, name, kind, target) {
            dump_verifier_log(name, &e);
            missing.push(format!("{name} ({target}): {e}"));
        }
    }
    if let Err(e) = zeroed {
        missing.push(format!("{TREE_CLOSED_MAP_NAME} not emptied: {e}"));
    }
    let outcome = if missing.is_empty() {
        info!(
            programs = PROGRAMS.len(),
            "trusted-installer window per process tree: kernel programs attached"
        );
        Ok(())
    } else {
        let why = missing.join("; ");
        warn!(reason = %why, "trusted-installer window per process tree: NOT available (tree grants refused)");
        Err(why)
    };
    let _ = ATTACHED.set(outcome.clone());
    outcome
}

/// A debug-trigger build keeps a refused program's verifier log (the lab's
/// verifier check), as the BPF guard does for its own.
fn dump_verifier_log(program: &str, e: &str) {
    if !cfg!(feature = "debug-trigger") {
        return;
    }
    let path = format!("/run/northnarrow/verifier-{program}.log");
    if let Err(w) = antitamper_bpf::kernel_roots::write(&path, e) {
        warn!(error = %w, path, "tree window: could not write the verifier log");
    }
}

/// The links attached without a pin (no bpffs), held for the agent's life.
static HELD: parking_lot::Mutex<Vec<FdLink>> = parking_lot::Mutex::new(Vec::new());

fn zero_closed(ebpf: &mut Ebpf) -> Result<(), String> {
    let m = ebpf
        .map_mut(TREE_CLOSED_MAP_NAME)
        .ok_or_else(|| format!("{TREE_CLOSED_MAP_NAME} missing from the eBPF object"))?;
    let mut a: Array<&mut MapData, [u64; 2]> = Array::try_from(m).map_err(|e| e.to_string())?;
    a.set(0, &[0u64; 2], 0).map_err(|e| e.to_string())
}

fn attach_one(
    ebpf: &mut Ebpf,
    btf: &Btf,
    pin_root: Option<&Path>,
    name: &str,
    kind: Kind,
    target: &str,
) -> Result<(), String> {
    let prog = ebpf
        .program_mut(name)
        .ok_or_else(|| format!("program {name} missing from the eBPF object"))?;
    // load and attach the fresh program: a prior boot's pinned one still
    // runs beside it (never a moment without the judge)
    let fd_link: FdLink = match kind {
        Kind::Lsm => {
            let p = <&mut Lsm>::try_from(prog).map_err(|e| e.to_string())?;
            p.load(target, btf).map_err(|e| format!("{e:#}"))?;
            let id = p.attach().map_err(|e| format!("{e:#}"))?;
            p.take_link(id).map_err(|e| format!("{e:#}"))?.into()
        }
        Kind::TpBtf => {
            let p = <&mut BtfTracePoint>::try_from(prog).map_err(|e| e.to_string())?;
            p.load(target, btf).map_err(|e| format!("{e:#}"))?;
            let id = p.attach().map_err(|e| format!("{e:#}"))?;
            p.take_link(id).map_err(|e| format!("{e:#}"))?.into()
        }
    };
    let Some(root) = pin_root else {
        // no bpffs: attached for this start (the descriptor kept for the
        // agent's life)
        HELD.lock().push(fd_link);
        return Ok(());
    };
    let (prog_path, link_path) = pin_paths(root, name);
    antitamper_bpf::purge_stale_pin(&link_path);
    antitamper_bpf::purge_stale_pin(&prog_path);
    let prog = ebpf
        .program_mut(name)
        .ok_or_else(|| format!("program {name} missing from the eBPF object"))?;
    let fd = prog.fd().map_err(|e| format!("{name}: {e}"))?;
    antitamper_bpf::held::pin_prog(fd, &prog_path)
        .map_err(|e| format!("pinning {name} to {}: {e:#}", prog_path.display()))?;
    antitamper_bpf::held::pin_link(fd_link, &link_path)
        .map_err(|e| format!("pinning {name}'s link to {}: {e:#}", link_path.display()))?;
    Ok(())
}

/// What a tree window lacks on this kernel and this start (`[]`: nothing):
/// the programs not attached ([`attach`]), and the [`REQUIRED_FIELDS`] the
/// running kernel's BTF does not have (`absent`). A tree grant is refused
/// while it names anything.
pub fn missing_from(attached: Option<&Result<(), String>>, absent: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    match attached {
        Some(Ok(())) => {}
        Some(Err(why)) => out.push(format!("programs: {why}")),
        None => out.push("programs: not attached this start (no deny hook)".to_string()),
    }
    for f in REQUIRED_FIELDS {
        if absent.contains(&f) {
            out.push(format!("kernel field {f} absent"));
        }
    }
    out
}

/// [`missing_from`] for this start, and (lot 2.3a, the key files, the review of
/// #647: fail-closed) the key files the pinned `INODE_EXT` under
/// `pin_root` does not keep now (`filesystem::key_files_not_kept`: a key
/// rotated or bootstrapped since the start is registered first). No pin
/// root: the arming refuses on its own.
pub fn manifest_missing(pin_root: Option<&Path>) -> Vec<String> {
    let absent: Vec<&str> = super::btf_revalidate::resolved()
        .map(|r| r.absent.iter().map(|m| m.name).collect())
        .unwrap_or_default();
    let mut out = missing_from(ATTACHED.get(), &absent);
    if let Some(root) = pin_root {
        out.extend(super::filesystem::key_files_not_kept(root));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_program_has_a_unique_name_within_the_kernel_s_fifteen_bytes() {
        let mut seen = std::collections::BTreeSet::new();
        for (name, _, _) in PROGRAMS {
            let short: String = name.chars().take(15).collect();
            assert!(seen.insert(short), "{name}");
            assert!(name.starts_with("tree_"), "{name}");
        }
    }

    #[test]
    fn the_fork_is_attached_last_and_the_exit_first() {
        assert_eq!(PROGRAMS[0].0, "tree_exit");
        assert_eq!(PROGRAMS[PROGRAMS.len() - 1].0, "tree_fork");
    }

    #[test]
    fn a_tree_window_needs_every_program_and_every_field() {
        assert!(missing_from(Some(&Ok(())), &[]).is_empty());
        let m = missing_from(
            Some(&Err("tree_fork (sched_process_fork): EINVAL".into())),
            &[],
        );
        assert_eq!(m.len(), 1);
        assert!(m[0].contains("tree_fork"));
        let m = missing_from(None, &[]);
        assert_eq!(m.len(), 1);
        let m = missing_from(
            Some(&Ok(())),
            &["TASK_STRUCT_SECCOMP_MODE_OFFSET", "UNRELATED"],
        );
        assert_eq!(
            m,
            vec!["kernel field TASK_STRUCT_SECCOMP_MODE_OFFSET absent".to_string()]
        );
    }

    #[test]
    fn the_required_fields_are_revalidated_optional_entries() {
        for f in REQUIRED_FIELDS {
            let spec = common::btf_offsets::REVALIDATE
                .iter()
                .find(|s| s.name == f)
                .unwrap_or_else(|| panic!("{f} not revalidated"));
            assert!(spec.optional, "{f}");
        }
    }

    #[test]
    fn the_programs_are_the_object_s() {
        let src = include_str!(concat!(
            env!("NN_REPO_ROOT"),
            "/agent-ebpf/src/window_tree.rs"
        ));
        for (name, kind, target) in PROGRAMS {
            let attr = match kind {
                Kind::Lsm => format!("#[lsm(hook = \"{target}\")]\npub fn {name}("),
                Kind::TpBtf => {
                    format!("#[btf_tracepoint(function = \"{target}\")]\npub fn {name}(")
                }
            };
            assert!(src.contains(&attr), "{attr}");
        }
        assert!(src.contains(&format!(
            "pub static {TREE_CLOSED_MAP_NAME}: Array<[u64; 2]> = Array::pinned(1, 0);"
        )));
    }
}
