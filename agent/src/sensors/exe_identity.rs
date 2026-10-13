//! Tappa 10.9 step 2 — userland half of the exec sensor on LSM
//! `bprm_check_security` (`agent-ebpf/src/exec_lsm.rs`, design
//! `docs/design/TAPPA10_9_SENSOR_ATTACH_POINTS_DESIGN.md` §11).
//!
//! - The mode: [`want_lsm`] (the `--exec-sensor` switch) before the
//!   multiplexer starts, [`attach`] there, [`lsm_active`] after.
//! - [`resolve`] turns the record's filesystem-relative path into an
//!   absolute one with the mount table, before any consumer reads the
//!   event (review 61: the exec rules read `exe.path_or(filename)`).

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{anyhow, Context, Result};
use aya::programs::Lsm;
use aya::{Btf, Ebpf};
use common::btf_offsets::{slot, BTF_OFFSETS_ABSENT};
use common::Event;
use parking_lot::Mutex;
use tracing::{info, warn};

use crate::sensors::open_sensor::MountTable;

/// The LSM program in the eBPF object.
pub const EXEC_LSM_PROGRAM: &str = "exec_check_lsm";

static LSM_WANTED: AtomicBool = AtomicBool::new(true);
static LSM_ACTIVE: AtomicBool = AtomicBool::new(false);

/// `--exec-sensor lsm` (the default) or `tracepoint`; set before the
/// multiplexer starts.
pub fn want_lsm(on: bool) {
    LSM_WANTED.store(on, Ordering::Relaxed);
}

/// Whether the LSM exec sensor is the one attached.
pub fn lsm_active() -> bool {
    LSM_ACTIVE.load(Ordering::Relaxed)
}

/// The offsets the LSM program cannot do without, resolved on this
/// kernel: `linux_binprm.file`, `.filename` and `.interp`.
fn offsets_resolved() -> Option<&'static str> {
    let Some(r) = crate::anti_tamper::btf_revalidate::resolved() else {
        return Some("no kernel BTF");
    };
    for (s, name) in [
        (slot::LINUX_BINPRM_FILE_OFFSET, "linux_binprm.file"),
        (slot::LINUX_BINPRM_FILENAME_OFFSET, "linux_binprm.filename"),
        (slot::LINUX_BINPRM_INTERP_OFFSET, "linux_binprm.interp"),
    ] {
        match r.values.iter().find(|(k, _)| *k == s) {
            Some((_, v)) if *v != BTF_OFFSETS_ABSENT => {}
            _ => return Some(name),
        }
    }
    None
}

/// Attach the exec sensor: the LSM program when wanted and loadable,
/// else `sys_enter_execve` (`attach_tracepoint`, from the multiplexer).
/// Returns which one runs.
pub fn attach(
    ebpf: &mut Ebpf,
    attach_tracepoint: impl FnOnce(&mut Ebpf) -> Result<()>,
) -> Result<&'static str> {
    if !LSM_WANTED.load(Ordering::Relaxed) {
        info!("exec sensor: tracepoint mode (--exec-sensor tracepoint) — sys_enter_execve");
        attach_tracepoint(ebpf)?;
        return Ok("sys_enter_execve");
    }
    if let Some(missing) = offsets_resolved() {
        warn!(
            missing,
            "exec sensor: an offset the LSM program needs is missing — attaching sys_enter_execve"
        );
        attach_tracepoint(ebpf)?;
        return Ok("sys_enter_execve");
    }
    match attach_lsm(ebpf) {
        Ok(()) => {
            LSM_ACTIVE.store(true, Ordering::Relaxed);
            info!(
                program = EXEC_LSM_PROGRAM,
                "exec sensor armed on LSM bprm_check_security (Tappa 10.9 step 2)"
            );
            Ok(EXEC_LSM_PROGRAM)
        }
        Err(e) => {
            warn!(
                error = %verifier_tail(&e),
                "exec sensor: the LSM program was refused — attaching sys_enter_execve"
            );
            attach_tracepoint(ebpf)?;
            Ok("sys_enter_execve")
        }
    }
}

fn attach_lsm(ebpf: &mut Ebpf) -> Result<()> {
    let btf = Btf::from_sys_fs().context("loading vmlinux BTF for the exec sensor")?;
    let prog: &mut Lsm = ebpf
        .program_mut(EXEC_LSM_PROGRAM)
        .ok_or_else(|| anyhow!("program {EXEC_LSM_PROGRAM} missing from eBPF object"))?
        .try_into()
        .with_context(|| format!("program {EXEC_LSM_PROGRAM} is not LSM"))?;
    prog.load("bprm_check_security", &btf)
        .with_context(|| format!("verifier rejected `{EXEC_LSM_PROGRAM}`"))?;
    prog.attach()
        .with_context(|| format!("attaching `{EXEC_LSM_PROGRAM}`"))?;
    Ok(())
}

/// The error chain with a long verifier log cut to its last lines (the
/// reason is at the end).
pub(crate) fn verifier_tail(e: &anyhow::Error) -> String {
    const KEEP: usize = 30;
    let full = format!("{e:#}");
    let lines: Vec<&str> = full.lines().collect();
    if lines.len() <= KEEP {
        return full;
    }
    let skipped = lines.len() - KEEP;
    format!(
        "… [{skipped} verifier lines elided]\n{}",
        lines[skipped..].join("\n")
    )
}

static MOUNTS: Mutex<Option<MountTable>> = Mutex::new(None);

/// Make an exec event's path absolute: the root of the file's filesystem
/// mapped to its mount point. A root the table does not know (a mount of
/// another namespace, the memfd mount) leaves no path, so consumers fall
/// back to the caller's string, as before this sensor.
pub fn resolve(event: &mut Event) {
    let (pid, filename, exe) = match event {
        Event::ProcessSpawn {
            pid, filename, exe, ..
        }
        | Event::ExecCheck {
            pid, filename, exe, ..
        } => (*pid, filename.as_str(), exe),
        _ => return,
    };
    if exe.root != (0, 0) {
        let mut guard = MOUNTS.lock();
        let table = guard.get_or_insert_with(MountTable::load);
        match table.absolute(exe.root, &exe.path) {
            Some(abs) => exe.path = abs,
            None => exe.path.clear(),
        }
        exe.root = (0, 0);
    }
    // External audit PROC-002/003: without a path the kernel resolved
    // (tracepoint mode, or a file the sensor could not place), the rules
    // fell back on the string the caller passed to execve. A relative
    // `./payload` run from /tmp matched no staging rule, and
    // `/usr/bin/../../tmp/nsenter` passed R013/R017's standard-prefix
    // exemption. Give them the real path instead: the string normalised,
    // or the running image's when the string is relative. The flags are
    // untouched: nothing reads this as a kernel-resolved identity.
    if exe.path.is_empty() {
        if let Some(path) = fallback_exec_path(pid, filename) {
            exe.path = path;
        }
    }
}

/// External audit PROC-002/003: an exec path the rules can judge when the
/// kernel's is missing — `filename` with `.`, `..` and repeated slashes
/// resolved lexically when it is absolute (no I/O, no race), else the
/// target of `/proc/<pid>/exe` while the process still runs.
fn fallback_exec_path(pid: u32, filename: &str) -> Option<String> {
    if filename.starts_with('/') {
        return Some(lexically_normal(filename));
    }
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// `path` (absolute) with `.`, `..` and empty components resolved.
fn lexically_normal(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    format!("/{}", parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::ExeIdentity;

    fn spawn_with(exe: ExeIdentity) -> Event {
        Event::ProcessSpawn {
            pid: 1,
            ppid: 0,
            uid: 0,
            gid: 0,
            comm: "x".into(),
            filename: "./x".into(),
            timestamp_ns: 0,
            argv: vec![],
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe,
        }
    }

    /// External audit PROC-002/003: with no kernel path, the rules get
    /// the caller's string normalised, or the running image when it is
    /// relative — not the raw string.
    #[test]
    fn missing_kernel_path_falls_back_on_the_real_one() {
        let spawn = |pid: u32, filename: &str| Event::ProcessSpawn {
            pid,
            ppid: 0,
            uid: 0,
            gid: 0,
            comm: "x".into(),
            filename: filename.into(),
            timestamp_ns: 0,
            argv: vec![],
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
        };
        for (raw, want) in [
            ("/usr/bin/../../tmp/nsenter", "/tmp/nsenter"),
            ("//tmp/./payload", "/tmp/payload"),
            ("/var/tmp/../tmp/x", "/var/tmp/x"),
            ("/usr/bin//nsenter", "/usr/bin/nsenter"),
        ] {
            let mut e = spawn(1, raw);
            resolve(&mut e);
            let Event::ProcessSpawn { exe, filename, .. } = &e else {
                unreachable!()
            };
            assert_eq!(exe.path_or(filename), want, "{raw}");
            assert_eq!(filename, raw, "the caller's string is kept as evidence");
        }
        // relative: the running image (this test binary)
        let me = std::process::id();
        let mut e = spawn(me, "./payload");
        resolve(&mut e);
        let Event::ProcessSpawn { exe, filename, .. } = &e else {
            unreachable!()
        };
        let own = std::fs::read_link("/proc/self/exe").unwrap();
        assert_eq!(exe.path_or(filename), own.to_string_lossy());
        // relative, process gone: nothing better than the string
        let mut e = spawn(u32::MAX - 7, "./payload");
        resolve(&mut e);
        let Event::ProcessSpawn { exe, filename, .. } = &e else {
            unreachable!()
        };
        assert_eq!(exe.path_or(filename), "./payload");
    }

    #[test]
    fn task_view_paths_are_kept() {
        let mut e = spawn_with(ExeIdentity {
            path: "/tmp/x".into(),
            ..Default::default()
        });
        resolve(&mut e);
        let Event::ProcessSpawn { exe, filename, .. } = &e else {
            unreachable!()
        };
        assert_eq!(exe.path_or(filename), "/tmp/x");
    }

    #[test]
    fn unknown_roots_fall_back_to_the_callers_string() {
        let mut e = spawn_with(ExeIdentity {
            path: "/x".into(),
            root: (u64::MAX, u64::MAX),
            ..Default::default()
        });
        resolve(&mut e);
        let Event::ProcessSpawn { exe, filename, .. } = &e else {
            unreachable!()
        };
        assert_eq!(exe.path_or(filename), "./x");
    }

    #[test]
    fn the_root_filesystem_maps_to_slash() {
        // `/` is mounted on every host: its key comes from stat("/").
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata("/").unwrap();
        let root = (
            crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev()),
            m.ino(),
        );
        let mut e = spawn_with(ExeIdentity {
            path: "/usr/bin/x".into(),
            root,
            ..Default::default()
        });
        resolve(&mut e);
        let Event::ProcessSpawn { exe, filename, .. } = &e else {
            unreachable!()
        };
        assert_eq!(exe.path_or(filename), "/usr/bin/x");
    }
}
