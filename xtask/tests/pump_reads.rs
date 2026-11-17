//! Lot 366: the exec pumps read a process's files only through the doors
//! of `nn_linux::sensors::pump_reads` and `antitamper_bpf::kernel_roots`
//! (`link_target`, `walk_judged`, `cached`), on the exec pumps' reader, and
//! hold no lock while a file is read — and this ratchet keeps it so.
//!
//! The exec pump and the exec-check pump read, for each exec, the file the
//! process runs, its root, the directory it was run from, an AppImage's
//! image and daemon, a module tool's script and library path. A read of a
//! path may wait on what the process's user controls; the doors read the
//! kernel's cached identity of a process's link, walk a path one name at a
//! time with every file system judged before a name is looked up in it,
//! and open a file only once it is judged.
//!
//! - **Reads.** A new site in the pumps' modules (and the multiplexer's
//!   pump steps) that reads a path by itself — [`MARKERS`]: a `metadata`,
//!   an open, a listing, a `canonicalize`, a link's text, a state file, an
//!   existence or kind check of a path, by `std::fs` (any spelling: `fs::`,
//!   an import, a `Path` method) or by `kernel_roots`' path readers — fails
//!   here until it goes through a door, or its file's pin in [`KNOWN`] is
//!   raised with why its paths are the kernel's (`/proc`'s own files) or
//!   root's (the system's module tool, the installed programs' list), or
//!   the call is a cached identity's (`Cached::is_dir`: memory).
//! - **Locks** (the review of #573, F1). In those modules, a function that
//!   takes a lock (`.lock()`) reads nothing — no marker, no door, no wait
//!   on the reader — directly or through a function of its module it calls:
//!   a read under a lock the pumps share held both pumps when the read did
//!   not answer.
//!
//! The scan is lexical over the production code (comments blanked, test
//! items left out); each rule is shown failing on planted sites, one per
//! spelling.

mod support;

use std::collections::{BTreeMap, BTreeSet};

use support::{matching_brace, product_code, repo_root};

/// The pumps' modules: what the exec pump and the exec-check pump run for
/// each exec.
const PUMP_FILES: &[&str] = &[
    "crates/nn-linux/src/sensors/exec_facts.rs",
    "crates/nn-linux/src/sensors/app_image.rs",
    "crates/nn-linux/src/sensors/kmod_exec.rs",
    "crates/nn-linux/src/sensors/exe_identity.rs",
    "crates/nn-linux/src/program_images.rs",
    "crates/nn-linux/src/sensors/multiplexer.rs",
];

/// The doors' module: its locks are held across no read either.
const DOORS: &str = "crates/nn-linux/src/sensors/pump_reads.rs";

/// The multiplexer's pump steps (the rest of that file is the sensors'
/// setup, before any pump runs): the lock rule reads these.
const STEPS: &[&str] = &[
    "resolved",
    "check_resolved",
    "reader_uid",
    "bounded_step",
    "bounded_step_in",
    "kmod_read_then_resolved",
];

/// A path read by itself: the kernel walks it, follows its links, crosses
/// its mounts and asks each file system on the way. Each spelling counted
/// once (none is a part of another).
const MARKERS: &[&str] = &[
    "metadata(",
    "exists(",
    "is_dir(",
    "is_file(",
    "is_symlink(",
    "canonicalize(",
    "read_dir(",
    "read_dir_max(",
    "read_link(",
    "read_state(",
    "read_to_string(",
    "fs::read(",
    "kernel_roots::read(",
    "kernel_roots::read_all(",
    "kernel_roots::read_text(",
    "kernel_roots::open(",
    "kernel_roots::open_crossing(",
    "File::open(",
    "OpenOptions",
    "use std::fs::{",
    // the re-check of #573 (N5): a mount table read by its path, and the
    // C library's path calls
    "mountinfo::read(",
    "MountTable::load",
    "libc::stat(",
    "libc::lstat(",
    "libc::statx(",
    "libc::fstatat(",
    "libc::open(",
    "libc::openat(",
    "libc::access(",
    "libc::faccessat(",
    "libc::readlink(",
    "libc::readlinkat(",
    "libc::opendir(",
];

/// An import of one of `std::fs`' functions by its own name (`use
/// std::fs::metadata;`): its calls are then bare.
fn fs_function_imports(text: &str) -> usize {
    text.match_indices("use std::fs::")
        .filter(|(at, _)| {
            let rest = &text[at + "use std::fs::".len()..];
            rest.starts_with(|c: char| c.is_ascii_lowercase())
        })
        .count()
}

fn count(text: &str) -> usize {
    MARKERS
        .iter()
        .map(|m| text.matches(m).count())
        .sum::<usize>()
        + fs_function_imports(text)
}

/// The files with sites: how many, and why their paths ask no file system
/// a user controls, or are no path at all.
const KNOWN: &[(&str, usize, &str)] = &[
    (
        "crates/nn-linux/src/sensors/exec_facts.rs",
        7,
        "`/proc/<pid>`'s own links' text (`exe`, `ns/mnt`, `fd/0`), its `environ` and `stat` \
         — procfs's own, opened beneath the `/proc` root the start anchored (the kernel \
         answers from the process's state); `Cached::is_dir` (the kernel's cached identity: \
         memory)",
    ),
    (
        "crates/nn-linux/src/sensors/app_image.rs",
        11,
        "the `/proc` root and `/proc/<pid>/fd` listed, `stat`, `status`, `fdinfo/<n>` read, \
         the `exe` and `fd/<n>` links' text, PID 1's `mountinfo` — procfs's own, beneath the \
         anchored `/proc` root, on the reader; `Cached::is_file` (memory)",
    ),
    (
        "crates/nn-linux/src/sensors/kmod_exec.rs",
        18,
        "`/proc/<pid>/environ`, `stat`, `status`, `exe`, `task`, and (lot 369) `ns/user`'s \
         link text and PID 1's (procfs's own, beneath the anchored root); the system's module tool and the initramfs builders at their fixed, \
         root-owned paths (`/usr/bin/kmod`, `/usr/sbin/update-initramfs`, …), on the reader; \
         `Cached::is_dir`/`is_file` (memory)",
    ),
    (
        "crates/nn-linux/src/sensors/exe_identity.rs",
        3,
        "`/proc/<pid>/exe`'s text (procfs's own link: the kernel's `d_path`, nothing looked \
         up on the file's file system); the agent's own descriptor's link \
         (`/proc/self/fd/<n>`: the `d_path` of the file it holds — lot 366's re-checks: an \
         exec no mount places, named by the very file whose identity from the kernel's cache \
         is the exec's); the agent's own mount table (`/proc/self/mountinfo`, procfs's own: \
         the kernel answers), each pump thread's own",
    ),
    (
        "crates/nn-linux/src/program_images.rs",
        18,
        "the installed programs' list (`/etc/shells`, the system's binary directories and \
         the runtimes' fixed paths, resolved and checked root-only at a refresh); the \
         installed program a running image is compared with, and a runtime at its recorded \
         path (root's); procfs's own `stat`/`status`; `Cached::is_dir`, `Metadata::is_file` \
         (memory)",
    ),
    (
        "crates/nn-linux/src/sensors/multiplexer.rs",
        3,
        "the sensors' setup before any pump runs: `/sys/kernel/btf/vmlinux` (sysfs), \
         `/proc/sys/kernel/perf_event_paranoid` (procfs); the module-load pump's own mount \
         table (procfs's own; not an exec pump) — no exec pump step reads by hand",
    ),
];

fn violations(code: &BTreeMap<String, String>) -> Vec<String> {
    let known: BTreeMap<&str, usize> = KNOWN.iter().map(|(f, n, _)| (*f, *n)).collect();
    let mut out = Vec::new();
    for file in PUMP_FILES {
        let Some(text) = code.get(*file) else {
            out.push(format!("{file}: a pump's module, not in the scan"));
            continue;
        };
        let n = count(text);
        match known.get(file) {
            None if n > 0 => out.push(format!(
                "{file}: {n} path read(s) by hand in an exec pump — read a process's link with \
                 `kernel_roots::link_target`, walk a path with `pump_reads::walk_in_root` / \
                 `walk_host` (every file system judged), open with `pump_reads::open_exe`, or \
                 list the file in KNOWN with why its paths ask no user's file system"
            )),
            Some(&pin) if n > pin => out.push(format!("{file}: {n} sites, {pin} known: a new one")),
            Some(&pin) if n < pin => out.push(format!(
                "{file}: {n} sites, {pin} known — lower the pin (the ratchet only goes down)"
            )),
            _ => {}
        }
    }
    for (file, _, _) in KNOWN {
        if !PUMP_FILES.contains(file) {
            out.push(format!("{file}: listed in KNOWN, not a pump's module"));
        }
    }
    out.extend(lock_violations(code));
    out
}

/// What a function that holds a lock must not do: read a path ([`MARKERS`]),
/// go through a door, or wait on the exec pumps' reader.
const READS: &[&str] = &[
    "link_target(",
    "walk_judged(",
    "walk_in_root(",
    "walk_host(",
    "open_exe(",
    "reopen_fd(",
    "kernel_roots::cached(",
    "read_to_end(",
    "dir_names_max(",
    "run_within(",
    "bounded(",
    ".run(",
];

/// The functions of `text` (production code): name and body, lexically —
/// `fn name` to the brace that closes its body.
fn functions(text: &str) -> Vec<(String, String)> {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out = Vec::new();
    for (at, _) in text.match_indices("fn ") {
        if at > 0 && text[..at].chars().next_back().is_some_and(ident) {
            continue;
        }
        let rest = &text[at + 3..];
        let name: String = rest.chars().take_while(|c| ident(*c)).collect();
        if name.is_empty() {
            continue;
        }
        // the body: the first `{` after the signature, outside its
        // parentheses and brackets (`-> [T; 2]`); a `;` first: none
        let mut depth = 0i32;
        let mut open = None;
        for (i, c) in rest.char_indices() {
            match c {
                '(' | '[' => depth += 1,
                ')' | ']' => depth -= 1,
                '{' if depth == 0 => {
                    open = Some(i);
                    break;
                }
                ';' if depth == 0 => break,
                _ => {}
            }
        }
        let Some(open) = open else {
            continue;
        };
        let len = matching_brace(&rest[open..]);
        out.push((name, rest[open..open + len].to_string()));
    }
    out
}

/// A lock taken, by any spelling (the re-check of #573, N5: a
/// `parking_lot::Mutex::lock(&m)`, a `try_lock()`, a `RwLock`'s guards).
const LOCKS: &[&str] = &[
    ".lock()",
    "Mutex::lock(",
    "try_lock(",
    "try_lock_for(",
    "try_lock_until(",
    "lock_arc(",
    ".read()",
    ".write()",
    "RwLock::read(",
    "RwLock::write(",
    "try_read(",
    "try_write(",
];

/// Whether `body` calls the function `name` (`name(`, after no identifier
/// character: `f(`, `.f(`, `::f(`).
fn calls(body: &str, name: &str) -> bool {
    let pat = format!("{name}(");
    body.match_indices(&pat).any(|(at, _)| {
        at == 0
            || !body[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// The review of #573 (F1): in each pump module and the doors' module, a
/// function that takes a lock reads nothing, directly or through the
/// module's functions it calls (transitively).
fn lock_violations(code: &BTreeMap<String, String>) -> Vec<String> {
    let mut out = Vec::new();
    for file in PUMP_FILES.iter().chain([&DOORS]) {
        let Some(text) = code.get(*file) else {
            continue;
        };
        let mut fns = functions(text);
        if file.ends_with("multiplexer.rs") {
            fns.retain(|(n, _)| STEPS.contains(&n.as_str()));
            for step in STEPS {
                if !fns.iter().any(|(n, _)| n == step) {
                    out.push(format!(
                        "{file}: the pump step `{step}` is gone: list the steps"
                    ));
                }
            }
        }
        let direct = |b: &str| {
            MARKERS.iter().chain(READS).any(|m| b.contains(m)) || fs_function_imports(b) > 0
        };
        let mut reading: BTreeSet<String> = fns
            .iter()
            .filter(|(_, b)| direct(b))
            .map(|(n, _)| n.clone())
            .collect();
        loop {
            let more: Vec<String> = fns
                .iter()
                .filter(|(n, b)| !reading.contains(n) && reading.iter().any(|r| calls(b, r)))
                .map(|(n, _)| n.clone())
                .collect();
            if more.is_empty() {
                break;
            }
            reading.extend(more);
        }
        for (name, body) in &fns {
            if LOCKS.iter().any(|l| body.contains(l)) && reading.contains(name) {
                out.push(format!(
                    "{file}: `{name}` takes a lock and reads (or waits on the reader), directly \
                     or through what it calls — take the lock only to look and to publish, read \
                     with none held"
                ));
            }
        }
    }
    out
}

/// No exec pump reads a path by itself outside the doors, nor under a lock.
#[test]
fn the_exec_pumps_read_a_process_s_files_through_the_doors() {
    let code = product_code(&repo_root());
    let v = violations(&code);
    assert!(v.is_empty(), "{v:#?}");
    for (file, _, why) in KNOWN {
        assert!(why.len() > 20, "{file}: say why");
    }
    let doors = &code[DOORS];
    for door in [
        "pub fn walk_in_root",
        "pub fn walk_host",
        "pub fn open_exe",
        "pub fn bounded",
        "c.mnt_id",
    ] {
        assert!(doors.contains(door), "{door}");
    }
    let roots = &code["antitamper-bpf/src/kernel_roots.rs"];
    for door in [
        "pub fn link_target",
        "pub fn walk_judged",
        "AT_STATX_DONT_SYNC",
        "STATX_MNT_ID",
    ] {
        assert!(roots.contains(door), "{door}");
    }
}

/// Each spelling of a path read by hand, planted in a pump's module (the
/// review of #573's five ordinary spellings among them), fails; so does
/// one more in a listed file, and one in a pump step.
#[test]
fn every_spelling_of_a_path_read_by_hand_fails_the_ratchet() {
    let base = product_code(&repo_root());
    assert!(violations(&base).is_empty());
    let facts = "crates/nn-linux/src/sensors/exec_facts.rs";
    let image = "crates/nn-linux/src/sensors/exe_identity.rs";
    let steps = "crates/nn-linux/src/sensors/multiplexer.rs";
    for plant in [
        // the review of #573 (F6): its five
        "use std::fs; fs::metadata(p)",
        "p.is_dir()",
        "p.canonicalize()",
        "crate::state_read::read_state(p)",
        "antitamper_bpf::kernel_roots::read_link(dir.join(\"root\").join(rel))",
        // and their kin
        "use std::fs::metadata; metadata(p)",
        "use std::fs::{self}; fs::read(p)",
        "p.metadata()",
        "p.symlink_metadata()",
        "p.exists()",
        "p.try_exists()",
        "p.is_file()",
        "p.is_symlink()",
        "p.read_dir()",
        "p.read_link()",
        "fs::read_to_string(p)",
        "fs::read_link(p)",
        "antitamper_bpf::kernel_roots::metadata(dir.join(\"exe\"))",
        "antitamper_bpf::kernel_roots::symlink_metadata(p)",
        "antitamper_bpf::kernel_roots::exists(p)",
        "antitamper_bpf::kernel_roots::is_dir(p)",
        "antitamper_bpf::kernel_roots::open(p, libc::O_RDONLY)",
        "antitamper_bpf::kernel_roots::open_crossing(p, 0)",
        "antitamper_bpf::kernel_roots::read(p, 4096)",
        "antitamper_bpf::kernel_roots::read_all(p)",
        "antitamper_bpf::kernel_roots::read_text(p)",
        "antitamper_bpf::kernel_roots::read_to_string(p)",
        "antitamper_bpf::kernel_roots::read_dir(p)",
        "antitamper_bpf::kernel_roots::read_dir_max(p, 9)",
        "std::fs::metadata(p)",
        "std::fs::symlink_metadata(p)",
        "std::fs::canonicalize(p)",
        "std::fs::read_dir(p)",
        "std::fs::read(p)",
        "std::fs::read_to_string(p)",
        "std::fs::File::open(p)",
        "std::fs::OpenOptions::new().read(true).open(p)",
        "reader.read_state(p)",
        // the re-check of #573 (N5): its two
        "crate::mountinfo::read(p)",
        "unsafe { libc::stat(c.as_ptr(), &mut st) }",
        // and their kin
        "crate::mountinfo::MountTable::load(p)",
        "unsafe { libc::lstat(c.as_ptr(), &mut st) }",
        "unsafe { libc::statx(0, c.as_ptr(), 0, 0, &mut sx) }",
        "unsafe { libc::fstatat(0, c.as_ptr(), &mut st, 0) }",
        "unsafe { libc::open(c.as_ptr(), 0) }",
        "unsafe { libc::openat(0, c.as_ptr(), 0) }",
        "unsafe { libc::access(c.as_ptr(), 0) }",
        "unsafe { libc::faccessat(0, c.as_ptr(), 0, 0) }",
        "unsafe { libc::readlink(c.as_ptr(), b.as_mut_ptr(), 1) }",
        "unsafe { libc::readlinkat(0, c.as_ptr(), b.as_mut_ptr(), 1) }",
        "unsafe { libc::opendir(c.as_ptr()) }",
    ] {
        for file in [facts, image, steps] {
            let mut code = base.clone();
            let body = if file == steps {
                // inside a pump step
                code[file].replacen(
                    "fn check_resolved(raw: &ExecCheckRaw, e: Event) -> (Event, [Option<Event>; 2]) {",
                    &format!(
                        "fn check_resolved(raw: &ExecCheckRaw, e: Event) -> (Event, [Option<Event>; 2]) {{ {plant};"
                    ),
                    1,
                )
            } else {
                format!("{}\nfn planted() {{ {plant}; }}", code[file])
            };
            assert_ne!(body, code[file], "{plant} planted in {file}");
            code.insert(file.to_string(), body);
            let v = violations(&code);
            assert!(
                v.iter().any(|m| m.starts_with(file)),
                "{plant} in {file}: {v:#?}"
            );
        }
    }
}

/// The review of #573 (F1): a lock held while a file is read — directly,
/// through a door, through a function of the module that reads, or while
/// waiting on the reader — fails, in a pump's module and in the doors'.
#[test]
fn a_lock_held_across_a_read_fails_the_ratchet() {
    let base = product_code(&repo_root());
    assert!(
        lock_violations(&base).is_empty(),
        "{:#?}",
        lock_violations(&base)
    );
    for (file, plant) in [
        (
            "crates/nn-linux/src/sensors/app_image.rs",
            "fn planted(p: &Path, r: &TieRead) -> bool { let mut g = PUMP.lock(); let f = read_step(p, r); g.publish(r, &f) }",
        ),
        (
            "crates/nn-linux/src/sensors/app_image.rs",
            "fn planted(p: &Path) { let _g = PUMP.lock(); let _ = crate::mountinfo::read(p); }",
        ),
        (
            "crates/nn-linux/src/sensors/kmod_exec.rs",
            "fn planted(e: &Event) { BUILDERS.lock().record(e, builder_exec(Path::new(\"/\"), e)); }",
        ),
        (
            "crates/nn-linux/src/program_images.rs",
            "fn planted(p: &Path) { let _g = RUNTIMES.refreshed.lock(); let _ = installed_runtimes_under(p); }",
        ),
        (
            DOORS,
            "fn planted(m: &Mutex<Mounts>) { let g = m.lock(); let _ = crate::mountinfo::read(&g.source); }",
        ),
        (
            DOORS,
            "fn planted() { let _g = STALE.lock(); let _ = bounded(0, \"x\", || ()); }",
        ),
        // the re-check of #573 (N5): a lock taken by another spelling
        (
            "crates/nn-linux/src/sensors/app_image.rs",
            "fn planted(record: &Mutex<AppImages>, r: &TieRead) -> bool { let g = parking_lot::Mutex::lock(record); let found = read_step(Path::new(\"/proc\"), r); drop(g); found == Found::Nothing }",
        ),
        (
            "crates/nn-linux/src/sensors/app_image.rs",
            "fn planted(record: &Mutex<AppImages>, r: &TieRead) -> bool { let Some(_g) = record.try_lock() else { return false }; read_step(Path::new(\"/proc\"), r) == Found::Nothing }",
        ),
        (
            "crates/nn-linux/src/sensors/app_image.rs",
            "fn planted(m: &parking_lot::RwLock<u8>, r: &TieRead) { let _g = m.read(); let _ = read_step(Path::new(\"/proc\"), r); }",
        ),
        (
            "crates/nn-linux/src/sensors/app_image.rs",
            "fn planted(m: &parking_lot::RwLock<u8>, r: &TieRead) { let _g = m.write(); let _ = read_step(Path::new(\"/proc\"), r); }",
        ),
        (
            "crates/nn-linux/src/sensors/app_image.rs",
            "fn planted(m: &Mutex<u8>, r: &TieRead) { let _g = m.try_lock_for(std::time::Duration::ZERO); let _ = read_step(Path::new(\"/proc\"), r); }",
        ),
    ] {
        let mut code = base.clone();
        let more = format!("{}\n{plant}", code[file]);
        code.insert(file.to_string(), more);
        let v = lock_violations(&code);
        assert!(
            v.iter().any(|m| m.starts_with(file) && m.contains("`planted`")),
            "{plant} in {file}: {v:#?}"
        );
    }
}
