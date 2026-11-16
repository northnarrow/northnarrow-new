//! Tappa 10.9 step 2 — userland half of the exec sensor on LSM
//! `bprm_check_security` (`agent-ebpf/src/exec_lsm.rs`, design
//! `docs/design/TAPPA10_9_SENSOR_ATTACH_POINTS_DESIGN.md` §11).
//!
//! - The mode: the `--exec-sensor` switch in the multiplexer's load plan,
//!   [`attach`] there, which says which program runs (R11c, lab PR 264:
//!   they were process-wide switches, `want_lsm` and `lsm_active`).
//! - [`resolve`] turns the record's filesystem-relative path into an
//!   absolute one with the mount table, before any consumer reads the
//!   event (review 61: the exec rules read `exe.path_or(filename)`).

use anyhow::{anyhow, Context, Result};
use aya::programs::Lsm;
use aya::Ebpf;
use common::btf_offsets::{slot, BTF_OFFSETS_ABSENT};
use nn_model::Event;
use tracing::{info, warn};

use crate::boot::manifest::{AttachPoints, Took};
use crate::sensors::contract::attach as A;
use crate::sensors::open_sensor::MountTable;

/// The LSM program in the eBPF object.
pub const EXEC_LSM_PROGRAM: &str = "exec_check_lsm";

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

/// Which exec sensor the start wants: the LSM program, or the tracepoint
/// and why (R13, lab PR 271: the operator's choice, or `bpf` not in the
/// active LSM list).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Lsm,
    Tracepoint(&'static str),
}

/// The mode of `--exec-sensor` (`want_lsm`) on a kernel whose active LSM
/// list has (`lsm_absent` false) or lacks `bpf`.
pub fn mode(want_lsm: bool, lsm_absent: bool) -> Mode {
    match (want_lsm, lsm_absent) {
        (false, _) => Mode::Tracepoint("chosen with --exec-sensor tracepoint"),
        (true, true) => Mode::Tracepoint(crate::sensors::contract::BPF_LSM_ABSENT),
        (true, false) => Mode::Lsm,
    }
}

/// Attach the exec sensor: the LSM program when wanted ([`Mode::Lsm`]:
/// `--exec-sensor lsm`, the default, on a kernel that runs BPF LSM
/// programs) and loadable, else `sys_enter_execve` (`attach_tracepoint`,
/// from the multiplexer), noted in `points`. Returns which one runs
/// ([`EXEC_LSM_PROGRAM`]: the LSM one).
pub fn attach(
    ebpf: &mut Ebpf,
    mode: Mode,
    points: &AttachPoints,
    attach_tracepoint: impl FnOnce(&mut Ebpf) -> Result<()>,
) -> Result<&'static str> {
    if let Mode::Tracepoint(why) = mode {
        info!(
            reason = why,
            "exec sensor: tracepoint mode — sys_enter_execve"
        );
        attach_tracepoint(ebpf)?;
        tracepoint_fallback(points, why);
        return Ok("sys_enter_execve");
    }
    if let Some(missing) = offsets_resolved() {
        warn!(
            missing,
            "exec sensor: an offset the LSM program needs is missing — attaching sys_enter_execve"
        );
        attach_tracepoint(ebpf)?;
        tracepoint_fallback(
            points,
            &format!("the LSM program needs {missing}, not resolved"),
        );
        return Ok("sys_enter_execve");
    }
    match attach_lsm(ebpf) {
        Ok(()) => {
            info!(
                program = EXEC_LSM_PROGRAM,
                "exec sensor armed on LSM bprm_check_security (Tappa 10.9 step 2)"
            );
            points.note("exec", A::EXEC_LSM, Took::Whole);
            Ok(EXEC_LSM_PROGRAM)
        }
        Err(e) => {
            warn!(
                error = %verifier_tail(&e),
                "exec sensor: the LSM program was refused — attaching sys_enter_execve"
            );
            attach_tracepoint(ebpf)?;
            tracepoint_fallback(points, "the LSM program was refused by the kernel");
            Ok("sys_enter_execve")
        }
    }
}

/// Lab PR 218 (external review P0 C-13): the exec sensor on
/// `sys_enter_execve` reads the path from the caller's memory, which the
/// caller can rewrite before the kernel opens the file — a degradation,
/// signed and in `nn-admin status`, not only a WARN.
pub const EXEC_TRACEPOINT_DEGRADED: &str = "exec sensor on sys_enter_execve: the executed path is \
     read from the caller's memory (it can differ from the file the kernel runs)";

fn tracepoint_fallback(points: &AttachPoints, why: &str) {
    points.note("exec", A::EXEC_TRACEPOINT, Took::Fallback);
    crate::boot::degradation::report(
        "exec_sensor",
        &format!("{EXEC_TRACEPOINT_DEGRADED} — {why}"),
    );
}

fn attach_lsm(ebpf: &mut Ebpf) -> Result<()> {
    let btf = antitamper_bpf::kernel_roots::vmlinux_btf()
        .context("loading vmlinux BTF for the exec sensor")?;
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
pub fn verifier_tail(e: &anyhow::Error) -> String {
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

std::thread_local! {
    /// The review of #573 (F1): each pump thread's own table — no lock the
    /// exec pump and the exec-check pump share. It reads only the kernel's
    /// own state (`/proc/self/mountinfo`; the mount points, pinned in the
    /// kernel's cache while mounted).
    static MOUNTS: std::cell::RefCell<Option<MountTable>> = const { std::cell::RefCell::new(None) };
}

/// Make an exec event's path absolute: the root of the file's filesystem
/// mapped to its mount point. A root the table does not know (a mount of
/// another namespace, the memfd mount) leaves no path, so consumers fall
/// back to the caller's string, as before this sensor.
pub fn resolve(event: &mut Event) {
    let (pid, filename, filename_cut, exe) = match event {
        Event::ProcessSpawn {
            pid,
            filename,
            exe,
            filename_truncated,
            ..
        } => (*pid, filename.as_str(), *filename_truncated, exe),
        Event::ExecCheck {
            pid, filename, exe, ..
        } => (*pid, filename.as_str(), false, exe),
        _ => return,
    };
    if exe.root != (0, 0) {
        let abs = MOUNTS.with_borrow_mut(|m| {
            let table = m.get_or_insert_with(MountTable::load);
            table
                .absolute(exe.root, &exe.path)
                .or_else(|| placed_by_process(pid, (exe.dev, exe.ino), &exe.path, table))
        });
        match abs {
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
        if let Some(path) = fallback_exec_path(pid, filename, filename_cut) {
            exe.path = path;
        }
    }
}

/// Lot 366 (the re-check of #573, btrfs): the path of an exec whose root
/// the table does not place, by the process itself — the file
/// `/proc/<pid>/exe` leads to, when it is the exec's file (its identity from
/// the kernel's cache, the same as the LSM program's by the mount it is
/// reached through: [`crate::mountinfo::same_exec_file`]) on a mount of
/// this process's own table: that link's text (the kernel's `d_path`,
/// nothing asked of the file system), its last name the walk's. A btrfs
/// subvolume's file is walked by the kernel up to its file system's own
/// root, which no mount shows when only subvolumes are mounted (a `/home`
/// on btrfs, as Fedora and openSUSE lay it out): such an exec was unplaced,
/// and the table's re-read for it left the next mount (an AppImage's) not
/// placed either, its programs then judged by the caller's string. `None`
/// when the process runs another file now, in another namespace's mount,
/// or the file is gone.
fn placed_by_process(
    pid: u32,
    kernel: (u64, u64),
    walked: &str,
    table: &MountTable,
) -> Option<String> {
    let link = std::path::PathBuf::from(format!("/proc/{pid}/exe"));
    placed_by_link(&link, kernel, walked, table)
}

/// [`placed_by_process`] by the process's link `link`. The re-check 2 of
/// #573 (M2): the text is read from the very file whose identity was
/// checked — the agent's own descriptor of it (`/proc/self/fd/<n>`: the
/// kernel's `d_path` of that open file) — never from the link a second
/// time: a process that re-execs between two lookups of its link could
/// have had an exec named by the next file's path.
fn placed_by_link(
    link: &std::path::Path,
    kernel: (u64, u64),
    walked: &str,
    table: &MountTable,
) -> Option<String> {
    use std::os::fd::AsRawFd;
    let (file, c) = antitamper_bpf::kernel_roots::link_target(link).ok()?;
    let mount = table.mount_of(c.mnt_id)?;
    if !crate::mountinfo::same_exec_file(kernel, &c, Some(mount)) {
        return None;
    }
    let own = format!("/proc/self/fd/{}", file.as_raw_fd());
    let text = antitamper_bpf::kernel_roots::read_link(own).ok()?;
    drop(file);
    let text = text.to_str()?;
    let last = |p: &str| p.rsplit('/').next().map(str::to_owned);
    (text.starts_with('/') && last(text) == last(walked)).then(|| text.to_owned())
}

/// External audit PROC-002/003: an exec path the rules can judge when the
/// kernel's is missing — `filename` with `.`, `..` and repeated slashes
/// resolved lexically when it is absolute (no I/O, no race), else the
/// target of `/proc/<pid>/exe` while the process still runs.
///
/// External audit EBPF-021: a string the kernel cut (`cut`) is never
/// resolved lexically: what followed the cut may climb out of any prefix
/// (`/usr/bin/./././…/../../tmp/sh` cut inside the `./` run normalised to
/// `/usr/bin`). Only the running image names it then.
fn fallback_exec_path(pid: u32, filename: &str, cut: bool) -> Option<String> {
    if filename.starts_with('/') && !cut {
        return Some(lexically_normal(filename));
    }
    antitamper_bpf::kernel_roots::read_link(format!("/proc/{pid}/exe"))
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
    use nn_model::ExeIdentity;

    /// Lot 366 (the re-check of #573, btrfs): an exec whose root no mount
    /// of the table places (a btrfs subvolume's file: the kernel walks up
    /// to the file system's own root) is placed by the process itself —
    /// `/proc/<pid>/exe`'s text, when that link leads to the exec's file
    /// (by the kernel's identity) on a mount of this process's table, its
    /// last name the walk's; else it is not placed (the caller's string, as
    /// before). Fails where such an exec was always unplaced (a79a10b9).
    #[test]
    fn an_exec_no_mount_places_is_placed_by_its_process() {
        let me = std::env::current_exe().unwrap();
        let name = me.file_name().unwrap().to_str().unwrap().to_owned();
        let c = antitamper_bpf::kernel_roots::cached(&std::fs::File::open(&me).unwrap()).unwrap();
        let spawn = |dev: u64, ino: u64, walked: &str| {
            let mut e = nn_core::decision::rules::testutil::spawn("x", "/the/caller/string");
            if let Event::ProcessSpawn { pid, exe, .. } = &mut e {
                *pid = std::process::id();
                *exe = ExeIdentity {
                    path: walked.into(),
                    dev,
                    ino,
                    root: (1, 4_242_424),
                    flags: common::wire::exe::exe_flags::KNOWN,
                    ..Default::default()
                };
            }
            resolve(&mut e);
            match e {
                Event::ProcessSpawn { exe, .. } => exe.path,
                _ => unreachable!(),
            }
        };
        let text = antitamper_bpf::kernel_roots::read_link(std::path::Path::new("/proc/self/exe"))
            .unwrap();
        assert_eq!(
            spawn(c.dev, c.ino, &format!("/subvol/{name}")),
            text.to_str().unwrap(),
            "placed by the process's own link"
        );
        assert_eq!(
            spawn(c.dev, c.ino + 1, &format!("/subvol/{name}")),
            "/the/caller/string",
            "another file: not placed"
        );
        assert_eq!(
            spawn(c.dev, c.ino, "/subvol/another-name"),
            "/the/caller/string",
            "another name: not placed"
        );
        // its mount not in the table (another namespace's): not placed
        let t = tempfile::tempdir().unwrap();
        std::fs::write(t.path().join("mi"), "").unwrap();
        let empty = MountTable::load_from(&t.path().join("mi"));
        assert_eq!(
            placed_by_process(
                std::process::id(),
                (c.dev, c.ino),
                &format!("/subvol/{name}"),
                &empty
            ),
            None
        );
    }

    /// The re-check 2 of #573 (M2): the path an unplaced exec is given is
    /// the text of the very file whose identity was checked (the agent's
    /// descriptor of it), never a second lookup of the link — here a link
    /// whose own text names the file by another spelling (through a
    /// directory link), as a re-exec between two lookups would have named
    /// the next file: the file's own path, not the link's text. Fails where
    /// the link was read again (f7dd98ce: `…/via/app`).
    #[test]
    fn an_unplaced_exec_is_named_by_the_very_file_checked() {
        let t = tempfile::tempdir().unwrap();
        let real = t.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("app"), b"x").unwrap();
        std::os::unix::fs::symlink(&real, t.path().join("via")).unwrap();
        let link = t.path().join("exe");
        std::os::unix::fs::symlink(t.path().join("via").join("app"), &link).unwrap();
        let c =
            antitamper_bpf::kernel_roots::cached(&std::fs::File::open(real.join("app")).unwrap())
                .unwrap();
        let table = MountTable::load();
        let own = std::fs::canonicalize(real.join("app")).unwrap();
        assert_eq!(
            placed_by_link(&link, (c.dev, c.ino), "/subvol/app", &table).as_deref(),
            own.to_str(),
            "the checked file's own path"
        );
        assert_eq!(
            placed_by_link(&link, (c.dev, c.ino + 1), "/subvol/app", &table),
            None,
            "another file: not placed"
        );
    }

    /// Lot 366 (the re-check of #573, btrfs): the LSM program's identity of
    /// an exec's file and the kernel's cache of it agree by device and
    /// inode — or, on btrfs, by inode on the mount the file is reached
    /// through when the LSM program named the file system's own device
    /// (btrfs loaded after the agent started); another inode, another
    /// device, a mount that is not btrfs, or no mount known: not the file.
    #[test]
    fn an_exec_s_file_is_the_same_by_its_mount_on_btrfs() {
        let c = antitamper_bpf::kernel_roots::Cached {
            dev: 47,
            ino: 258,
            mode: libc::S_IFREG | 0o755,
            nlink: 1,
            uid: 1000,
            mnt_id: 61,
        };
        use crate::mountinfo::same_exec_file as same;
        assert!(same((47, 258), &c, None), "the subvolume's own device");
        assert!(
            same((44, 258), &c, Some((44, true))),
            "the file system's, on btrfs"
        );
        assert!(!same((44, 259), &c, Some((44, true))), "another inode");
        assert!(!same((45, 258), &c, Some((44, true))), "another device");
        assert!(!same((44, 258), &c, Some((44, false))), "not btrfs");
        assert!(!same((44, 258), &c, None), "no mount known");
    }

    /// R13 (lab PR 271): the LSM program only when wanted on a kernel that
    /// runs BPF LSM programs; else the tracepoint, and why.
    #[test]
    fn the_exec_sensor_s_mode() {
        assert_eq!(mode(true, false), Mode::Lsm);
        assert_eq!(
            mode(true, true),
            Mode::Tracepoint(crate::sensors::contract::BPF_LSM_ABSENT)
        );
        assert_eq!(
            mode(false, false),
            Mode::Tracepoint("chosen with --exec-sensor tracepoint")
        );
        assert_eq!(
            mode(false, true),
            mode(false, false),
            "the operator's choice first"
        );
    }

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
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
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
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
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

    /// External audit EBPF-021: a caller's string the kernel cut is not
    /// normalised into a path — `/usr/bin/` followed by enough `./` gives
    /// `/usr/bin/…` whatever came after the cut. The running image names
    /// the file; without it the path stays unknown.
    #[test]
    fn a_cut_callers_string_is_not_normalised() {
        let cut_spawn = |pid: u32, filename: &str| {
            let mut e = spawn_with(ExeIdentity::default());
            if let Event::ProcessSpawn {
                pid: p,
                filename: f,
                filename_truncated,
                ..
            } = &mut e
            {
                *p = pid;
                *f = filename.to_string();
                *filename_truncated = true;
            }
            e
        };
        let cut = format!("/usr/bin/{}", "./".repeat(123));
        // the process runs: its image
        let mut e = cut_spawn(std::process::id(), &cut);
        resolve(&mut e);
        let Event::ProcessSpawn { exe, .. } = &e else {
            unreachable!()
        };
        let own = std::fs::read_link("/proc/self/exe").unwrap();
        assert_eq!(exe.path, own.to_string_lossy());
        // gone: no path is made up from the string
        let mut e = cut_spawn(u32::MAX - 7, &cut);
        resolve(&mut e);
        let Event::ProcessSpawn { exe, filename, .. } = &e else {
            unreachable!()
        };
        assert!(exe.path.is_empty(), "{}", exe.path);
        assert_eq!(filename, &cut, "the caller's string is kept as evidence");
        // the same string, whole: normalised as before
        let mut e = spawn_with(ExeIdentity::default());
        if let Event::ProcessSpawn { filename, .. } = &mut e {
            *filename = cut.clone();
        }
        resolve(&mut e);
        let Event::ProcessSpawn { exe, .. } = &e else {
            unreachable!()
        };
        assert_eq!(exe.path, "/usr/bin");
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
