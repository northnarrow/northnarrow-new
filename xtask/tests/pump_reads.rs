//! Lot 366: the exec pumps read a process's files only through the doors
//! of `nn_linux::sensors::pump_reads` and `antitamper_bpf::kernel_roots`
//! (`link_target`, `walk_judged`, `cached`), and this ratchet keeps it so.
//!
//! The exec pump and the exec-check pump read, for each exec, the file the
//! process runs, its root, the directory it was run from, an AppImage's
//! image and daemon, a module tool's script and library path. A `metadata`
//! of `/proc/<pid>/exe`, or of a path under `/proc/<pid>/root`, asked a
//! user's FUSE file system (`allow_other`) for an answer its daemon never
//! gave, and the pump waited with every exec behind it. The doors read the
//! kernel's cached identity of a process's link, walk a path one name at a
//! time with every file system judged by its device before a name is
//! looked up in it, and open a file only once it is judged.
//!
//! A new site in the pumps' modules that reads a path by itself —
//! [`MARKERS`]: a `metadata`, an open, a listing, a `canonicalize`, by
//! `std::fs` or by `kernel_roots`' path readers — fails here until it goes
//! through a door, or its file is listed in [`KNOWN`] with its count and
//! why its paths are the kernel's (`/proc`'s own files) or root's (the
//! system's module tool, the installed programs' list). The scan is
//! lexical over the production code (comments blanked, test items left
//! out); the rule is shown failing on planted sites, one per spelling.

mod support;

use std::collections::BTreeMap;

use support::{product_code, repo_root};

/// The pumps' modules: what the exec pump and the exec-check pump run for
/// each exec.
const PUMP_FILES: &[&str] = &[
    "crates/nn-linux/src/sensors/exec_facts.rs",
    "crates/nn-linux/src/sensors/app_image.rs",
    "crates/nn-linux/src/sensors/kmod_exec.rs",
    "crates/nn-linux/src/sensors/exe_identity.rs",
    "crates/nn-linux/src/program_images.rs",
];

/// A path read by itself: the kernel walks it, follows its links, crosses
/// its mounts and asks each file system on the way.
const MARKERS: &[&str] = &[
    "kernel_roots::metadata(",
    "kernel_roots::symlink_metadata(",
    "kernel_roots::exists(",
    "kernel_roots::is_dir(",
    "kernel_roots::open(",
    "kernel_roots::open_crossing(",
    "kernel_roots::read(",
    "kernel_roots::read_all(",
    "kernel_roots::read_text(",
    "kernel_roots::read_to_string(",
    "kernel_roots::read_dir(",
    "std::fs::metadata(",
    "std::fs::symlink_metadata(",
    "std::fs::canonicalize(",
    "std::fs::read_dir(",
    "std::fs::read(",
    "std::fs::read_to_string(",
    "File::open(",
    "OpenOptions",
];

fn count(text: &str) -> usize {
    MARKERS.iter().map(|m| text.matches(m).count()).sum()
}

/// The files with sites: how many, and why their paths ask no file system
/// a user mounts.
const KNOWN: &[(&str, usize, &str)] = &[
    (
        "crates/nn-linux/src/sensors/exec_facts.rs",
        2,
        "`/proc/<pid>/environ`, opened beneath the `/proc` root the start anchored: procfs's \
         own file (the kernel reads it from the process's anonymous memory only)",
    ),
    (
        "crates/nn-linux/src/sensors/app_image.rs",
        2,
        "the `/proc` root and `/proc/<pid>/fd`, listed beneath the anchored `/proc` root: \
         procfs's own directories",
    ),
    (
        "crates/nn-linux/src/sensors/kmod_exec.rs",
        4,
        "`/proc/<pid>/environ` and `/proc/<pid>/task` (procfs's own, beneath the anchored \
         root); the system's module tool and the initramfs builders at their fixed, root-owned \
         paths (`/usr/bin/kmod`, `/bin/kmod`, `/usr/sbin/update-initramfs`, …)",
    ),
    (
        "crates/nn-linux/src/program_images.rs",
        10,
        "the installed programs' list (`/etc/shells`, the system's binary directories and \
         the runtimes' fixed paths, resolved and checked root-only at a refresh); the \
         installed program a running image is compared with, and a runtime at its recorded \
         path (root's)",
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
    out
}

/// No exec pump reads a path by itself outside the doors.
#[test]
fn the_exec_pumps_read_a_process_s_files_through_the_doors() {
    let code = product_code(&repo_root());
    let v = violations(&code);
    assert!(v.is_empty(), "{v:#?}");
    for (file, _, why) in KNOWN {
        assert!(why.len() > 20, "{file}: say why");
    }
    let doors = &code["crates/nn-linux/src/sensors/pump_reads.rs"];
    for door in [
        "pub fn walk_in_root",
        "pub fn walk_host",
        "pub fn open_exe",
        "pub fn bounded",
    ] {
        assert!(doors.contains(door), "{door}");
    }
    let roots = &code["antitamper-bpf/src/kernel_roots.rs"];
    for door in [
        "pub fn link_target",
        "pub fn walk_judged",
        "AT_STATX_DONT_SYNC",
    ] {
        assert!(roots.contains(door), "{door}");
    }
}

/// Each spelling of a path read by hand, planted in a pump's module,
/// fails; so does one more in a listed file.
#[test]
fn every_spelling_of_a_path_read_by_hand_fails_the_ratchet() {
    let base = product_code(&repo_root());
    let facts = "crates/nn-linux/src/sensors/exec_facts.rs";
    let image = "crates/nn-linux/src/sensors/exe_identity.rs";
    for plant in [
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
        "std::fs::metadata(p)",
        "std::fs::symlink_metadata(p)",
        "std::fs::canonicalize(p)",
        "std::fs::read_dir(p)",
        "std::fs::read(p)",
        "std::fs::read_to_string(p)",
        "std::fs::File::open(p)",
        "std::fs::OpenOptions::new().read(true).open(p)",
    ] {
        for file in [facts, image] {
            let mut code = base.clone();
            let more = format!("{}\nfn planted() {{ {plant}; }}", code[file]);
            code.insert(file.to_string(), more);
            let v = violations(&code);
            assert!(
                v.iter().any(|m| m.starts_with(file)),
                "{plant} in {file}: {v:#?}"
            );
        }
    }
    assert!(violations(&base).is_empty());
}
