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
//! - **Lazy initialisers** (lot 1.7a). A `static`'s initialiser in those
//!   modules (a `LazyLock`'s closure: it runs under the once's lock, the
//!   first pump to touch it holding the other) reads nothing either.
//!
//! Lot 1.7a (stage S1, item F12): the scan reads the production code as
//! Rust (`support::ast`; test items left out). A read is a call by its name
//! — a method (`p.metadata()`), or a path through the file's imports
//! (`use std::fs as f; f::read`, `use … kernel_roots as kr`, `use libc::stat
//! as st`, `use std::fs::File as F`), in parentheses, or a reader passed as
//! a value (`.map(fs::read_to_string)`, `let f = fs::metadata;`) —, and a
//! lock any guard of `std`'s or `parking_lot`'s, or a once's
//! initialisation (`get_or_init`, `call_once`). The lexical scan (kept in
//! [`lexical`] only to show it) missed each spelling planted below. Each
//! rule is shown failing on planted sites, one per spelling.

mod support;

use std::collections::{BTreeMap, BTreeSet};

use support::ast::{self, Corpus, Index};
use support::repo_root;

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

/// The kernel's roots' module (its doors are asserted below).
const ROOTS: &str = "antitamper-bpf/src/kernel_roots.rs";

/// A path read by itself, by the name of the call (a method, or a path's
/// last segment): the kernel walks it, follows its links, crosses its
/// mounts and asks each file system on the way.
const READ_NAMES: &[&str] = &[
    "metadata",
    "symlink_metadata",
    "exists",
    "try_exists",
    "is_dir",
    "is_file",
    "is_symlink",
    "canonicalize",
    "read_dir",
    "read_dir_max",
    "read_link",
    "read_state",
    "read_to_string",
];

/// A path read by itself, by the end of the call's full path (through the
/// file's imports): `std::fs`' `read`, `kernel_roots`' path readers, an
/// open, the mount table's readers, the C library's path calls (the
/// re-check of #573, N5; lot 1.7a: their `64` forms, `realpath`, `statfs`).
const READ_PATHS: &[&[&str]] = &[
    &["fs", "read"],
    &["kernel_roots", "read"],
    &["kernel_roots", "read_all"],
    &["kernel_roots", "read_text"],
    &["kernel_roots", "open"],
    &["kernel_roots", "open_crossing"],
    &["File", "open"],
    &["mountinfo", "read"],
    &["MountTable", "load"],
    &["libc", "stat"],
    &["libc", "stat64"],
    &["libc", "lstat"],
    &["libc", "lstat64"],
    &["libc", "statx"],
    &["libc", "fstatat"],
    &["libc", "fstatat64"],
    &["libc", "open"],
    &["libc", "open64"],
    &["libc", "openat"],
    &["libc", "openat64"],
    &["libc", "access"],
    &["libc", "faccessat"],
    &["libc", "readlink"],
    &["libc", "readlinkat"],
    &["libc", "opendir"],
    &["libc", "realpath"],
    &["libc", "statfs"],
    &["libc", "statvfs"],
];

/// The system calls of a path by number (`libc::syscall(libc::SYS_openat2,
/// …)`), lot 1.7a.
const READ_SYSCALLS: &[&str] = &[
    "SYS_open",
    "SYS_openat",
    "SYS_openat2",
    "SYS_stat",
    "SYS_lstat",
    "SYS_newfstatat",
    "SYS_statx",
    "SYS_readlink",
    "SYS_readlinkat",
    "SYS_access",
    "SYS_faccessat",
    "SYS_faccessat2",
];

/// What a function that holds a lock must not do besides: go through a
/// door, or wait on the exec pumps' reader.
const DOOR_NAMES: &[&str] = &[
    "link_target",
    "walk_judged",
    "walk_in_root",
    "walk_host",
    "open_exe",
    "reopen_fd",
    "read_to_end",
    "dir_names_max",
    "run_within",
    "bounded",
];

/// A lock taken, by any spelling (the re-check of #573, N5: a
/// `parking_lot::Mutex::lock(&m)`, a `try_lock()`, a `RwLock`'s guards;
/// lot 1.7a: `parking_lot`'s recursive, upgradable and `Arc` guards, a
/// once's initialisation).
const LOCK_NAMES: &[&str] = &[
    "lock",
    "try_lock",
    "try_lock_for",
    "try_lock_until",
    "lock_arc",
    "try_lock_arc",
    "try_read",
    "try_write",
    "try_read_for",
    "try_write_for",
    "read_recursive",
    "try_read_recursive",
    "upgradable_read",
    "try_upgradable_read",
    "read_arc",
    "write_arc",
    "get_or_init",
    "get_or_try_init",
    "call_once",
    "call_once_force",
];

/// Whether the full paths of `segs` (through `ix`'s imports) end in a
/// reader of a path.
fn is_read_path(ix: &Index<'_>, segs: &[String]) -> bool {
    ix.full_paths(segs).iter().any(|p| {
        p.last().is_some_and(|l| READ_NAMES.contains(&l.as_str()))
            || READ_PATHS.iter().any(|t| ast::path_ends(p, t))
            || p.iter().any(|s| s == "OpenOptions")
    })
}

/// One site: its line, its function (or item), what it is.
#[derive(Clone)]
struct Site {
    line: usize,
    scope: Option<ast::FnId>,
    item: String,
    what: String,
}

impl std::fmt::Debug for Site {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: `{}` {}", self.line, self.item, self.what)
    }
}

/// The paths read by hand in `rel`: each call of a reader (a method, a
/// path through the imports, a reader passed as a value), each
/// `syscall` of a path by number.
fn reads(c: &Corpus<'_>, rel: &str) -> Vec<Site> {
    let ix = &c.files[rel];
    let mut out = Vec::new();
    for call in &ix.calls {
        let hit = match (&call.receiver, &call.path) {
            (Some(_), _) => READ_NAMES.contains(&call.name.as_str()),
            (None, Some(p)) if ix.full_paths(p).iter().any(|f| ast::path_ends(f, &["libc", "syscall"])) => {
                call.args.first().is_some_and(|a| {
                    matches!(ast::peel(a), syn::Expr::Path(p) if READ_SYSCALLS.contains(&ast::last(&p.path).as_str()))
                })
            }
            _ => false,
        };
        if hit {
            out.push(Site {
                line: call.line,
                scope: call.scope,
                item: call.item.clone(),
                what: format!("{}(…)", call.name),
            });
        }
    }
    for r in &ix.paths {
        if is_read_path(ix, &r.segs) {
            out.push(Site {
                line: r.line,
                scope: r.scope,
                item: r.item.clone(),
                what: if r.called {
                    format!("{}(…)", r.segs.join("::"))
                } else {
                    format!("{} (a reader as a value)", r.segs.join("::"))
                },
            });
        }
    }
    out.sort_by_key(|s| s.line);
    out
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
        27,
        "`/proc/<pid>/environ`, `stat` (lot 373: the exec's and its parent's start before the \
         package manager's walk), `status`, `exe`, `task`, and (lot 369) `ns/user`'s \
         link text and PID 1's (procfs's own, beneath the anchored root); lot 380: the \
         forker's `stat`, its `task` listing, each thread's `status` and `ns/user` link text \
         (procfs's own); the system's module tool and the initramfs builders at their fixed, \
         root-owned paths (`/usr/bin/kmod`, `/usr/sbin/update-initramfs`, …; lot 380: the \
         tool's mode and `security.capability` through its descriptor), on the reader; \
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
        23,
        "the installed programs' list (`/etc/shells`, the system's binary directories and \
         the runtimes' fixed paths, resolved and checked root-only at a refresh); the \
         installed program a running image is compared with, and a runtime at its recorded \
         path (root's); procfs's own `stat`/`status`, and (lot 381) a parent's threads \
         (`/proc/<pid>/task` listed) and their `children`, (the review of #588, F1) the \
         exec's own threads listed and each one's `stat`, (the re-check of #588, N1) its own \
         `stat` (`num_threads`) — procfs's own, beneath the \
         anchored `/proc` root; `Cached::is_dir`, `Metadata::is_file` (memory)",
    ),
    (
        "crates/nn-linux/src/sensors/multiplexer.rs",
        3,
        "the sensors' setup before any pump runs: `/sys/kernel/btf/vmlinux` (sysfs), \
         `/proc/sys/kernel/perf_event_paranoid` (procfs); the module-load pump's own mount \
         table (procfs's own; not an exec pump) — no exec pump step reads by hand",
    ),
];

/// The pumps' modules, the doors' and the roots', parsed: `(sources,
/// production code)`.
fn pump_sources() -> BTreeMap<String, String> {
    let root = repo_root();
    PUMP_FILES
        .iter()
        .chain([&DOORS, &ROOTS])
        .map(|f| {
            let text = std::fs::read_to_string(root.join(f)).unwrap_or_else(|e| panic!("{f}: {e}"));
            (f.to_string(), text)
        })
        .collect()
}

/// The violations of the pumps' modules in `c` (the files of `c` that are
/// pumps' modules or the doors').
fn violations(c: &Corpus<'_>) -> Vec<String> {
    let known: BTreeMap<&str, usize> = KNOWN.iter().map(|(f, n, _)| (*f, *n)).collect();
    let mut out = Vec::new();
    for file in PUMP_FILES {
        if !c.files.contains_key(*file) {
            continue;
        }
        let s = reads(c, file);
        let n = s.len();
        match known.get(file) {
            None if n > 0 => out.push(format!(
                "{file}: {n} path read(s) by hand in an exec pump, {s:?} — read a process's link with \
                 `kernel_roots::link_target`, walk a path with `pump_reads::walk_in_root` / \
                 `walk_host` (every file system judged), open with `pump_reads::open_exe`, or \
                 list the file in KNOWN with why its paths ask no user's file system"
            )),
            Some(&pin) if n > pin => out.push(format!("{file}: {n} sites, {pin} known, {s:?}: a new one")),
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
    out.extend(lock_violations(c));
    out
}

/// The review of #573 (F1): in each pump module and the doors' module, a
/// function that takes a lock reads nothing, directly or through the
/// module's functions it calls (transitively, or passes as a value); lot
/// 1.7a: nor does a `static`'s initialiser.
fn lock_violations(c: &Corpus<'_>) -> Vec<String> {
    let mut out = Vec::new();
    let mut known_used = BTreeSet::new();
    for file in PUMP_FILES.iter().chain([&DOORS]) {
        let Some(ix) = c.files.get(*file) else {
            continue;
        };
        let steps_only = file.ends_with("multiplexer.rs");
        if steps_only {
            for step in STEPS {
                if !ix.fns.iter().any(|f| f.name == *step) {
                    out.push(format!(
                        "{file}: the pump step `{step}` is gone: list the steps"
                    ));
                }
            }
        }
        let read_sites = reads(c, file);
        // what each function (or a static's initialiser, scope None by its
        // item) calls by name, and whether it reads or waits itself
        let key = |scope: Option<ast::FnId>, item: &str| match scope {
            Some(id) => format!("fn#{id}"),
            None => format!("item {item}"),
        };
        let mut direct: BTreeSet<String> =
            read_sites.iter().map(|s| key(s.scope, &s.item)).collect();
        let mut callees: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut locks: BTreeSet<String> = BTreeSet::new();
        for call in &ix.calls {
            let k = key(call.scope, &call.item);
            let full = call
                .path
                .as_ref()
                .map(|p| ix.full_paths(p))
                .unwrap_or_default();
            if DOOR_NAMES.contains(&call.name.as_str())
                || (call.receiver.is_some() && call.name == "run")
                || full
                    .iter()
                    .any(|p| ast::path_ends(p, &["kernel_roots", "cached"]))
            {
                direct.insert(k.clone());
            }
            let zero_arg_guard = call.receiver.is_some()
                && call.args.is_empty()
                && (call.name == "read" || call.name == "write");
            let path_guard = full.iter().any(|p| {
                p.len() >= 2
                    && ["Mutex", "RwLock", "ReentrantMutex"].contains(&p[p.len() - 2].as_str())
                    && ["lock", "read", "write", "try_lock", "try_read", "try_write"]
                        .contains(&p[p.len() - 1].as_str())
            });
            if LOCK_NAMES.contains(&call.name.as_str()) || zero_arg_guard || path_guard {
                locks.insert(k.clone());
            }
        }
        for r in &ix.paths {
            // a local (a parameter, a `let`) is no function of the module
            let local =
                r.segs.len() == 1 && r.scope.is_some_and(|id| ix.fns[id].is_local(&r.segs[0]));
            if let (Some(last), false) = (r.segs.last(), local) {
                callees
                    .entry(key(r.scope, &r.item))
                    .or_default()
                    .insert(last.clone());
            }
        }
        for call in &ix.calls {
            if call.receiver.is_some() {
                callees
                    .entry(key(call.scope, &call.item))
                    .or_default()
                    .insert(call.name.clone());
            }
        }
        // the module's functions by name, and whether each reads (transitively)
        let names: BTreeMap<String, Vec<String>> =
            ix.fns
                .iter()
                .enumerate()
                .fold(BTreeMap::new(), |mut m, (id, f)| {
                    m.entry(f.name.clone())
                        .or_insert_with(Vec::new)
                        .push(format!("fn#{id}"));
                    m
                });
        let mut reading = direct.clone();
        loop {
            let mut more = Vec::new();
            for (k, called) in &callees {
                if reading.contains(k) {
                    continue;
                }
                if called.iter().any(|n| {
                    names
                        .get(n)
                        .is_some_and(|ids| ids.iter().any(|i| reading.contains(i)))
                }) {
                    more.push(k.clone());
                }
            }
            if more.is_empty() {
                break;
            }
            reading.extend(more);
        }
        for (id, f) in ix.fns.iter().enumerate() {
            if steps_only && !STEPS.contains(&f.name.as_str()) {
                continue;
            }
            let k = format!("fn#{id}");
            if locks.contains(&k) && reading.contains(&k) {
                if let Some(n) = LOCK_KNOWN
                    .iter()
                    .position(|(kf, kn, _, _)| kf == file && *kn == f.item)
                {
                    known_used.insert(n);
                    continue;
                }
                out.push(format!(
                    "{file}: `{}` takes a lock and reads (or waits on the reader), directly \
                     or through what it calls — take the lock only to look and to publish, read \
                     with none held",
                    f.name
                ));
            }
        }
        for name in ix.consts.keys() {
            if reading.contains(&format!("item {name}")) {
                out.push(format!(
                    "{file}: `{name}`'s initialiser reads (a lazy initialiser runs under its \
                     once's lock: the first pump to touch it holds the other) — read in a function"
                ));
            }
        }
    }
    for (n, (file, item, _, owner)) in LOCK_KNOWN.iter().enumerate() {
        assert!(
            owner.len() > 3,
            "{file}: `{item}` in LOCK_KNOWN, who owns it"
        );
        if c.files.contains_key(*file) && !known_used.contains(&n) {
            out.push(format!(
                "{file}: `{item}` in LOCK_KNOWN, no such site any more"
            ));
        }
    }
    out
}

/// Lot 1.7a: the functions the AST scan finds holding a once's lock across
/// a read, and why no other pump waits on it: `(file, function, why, the
/// code that owns it)` — one entry per function, a new one fails.
const LOCK_KNOWN: &[(&str, &str, &str, &str)] = &[(
    DOORS,
    "Judge::process_table",
    "the process's own mount table, read once into the judge's own `OnceLock` — a fresh one \
     per `Judge::of_process` (a walk through one process's `/proc` entry, on the exec pumps' \
     reader): no other judgment shares it, so no other pump waits on its initialisation",
    "nn-linux sensors::pump_reads (the exec pumps' judge)",
)];

/// The corpus of `sources` parsed (production code).
fn parsed(sources: &BTreeMap<String, String>) -> BTreeMap<String, syn::File> {
    ast::parse_all(sources, true)
}

/// No exec pump reads a path by itself outside the doors, nor under a lock.
#[test]
fn the_exec_pumps_read_a_process_s_files_through_the_doors() {
    let sources = pump_sources();
    let p = parsed(&sources);
    let c = Corpus::of(&sources, &p);
    let v = violations(&c);
    assert!(v.is_empty(), "{v:#?}");
    for (file, _, why) in KNOWN {
        assert!(why.len() > 20, "{file}: say why");
    }
    let doors = ast::compact(&p[DOORS]);
    for door in [
        "pubfnwalk_in_root",
        "pubfnwalk_host",
        "pubfnopen_exe",
        "pubfnbounded",
        "c.mnt_id",
    ] {
        assert!(doors.contains(door), "{door}");
    }
    let roots = ast::compact(&p[ROOTS]);
    for door in [
        "pubfnlink_target",
        "pubfnwalk_judged",
        "AT_STATX_DONT_SYNC",
        "STATX_MNT_ID",
    ] {
        assert!(roots.contains(door), "{door}");
    }
}

/// Prints each pump module's sites and its lexical count (to fill
/// [`KNOWN`]): a no-op unless `NN_PRINT_PUMP_READS=1`.
#[test]
#[ignore = "prints the sites; NN_PRINT_PUMP_READS=1, run by hand when the table moves"]
fn print_the_sites() {
    if std::env::var("NN_PRINT_PUMP_READS").as_deref() != Ok("1") {
        return;
    }
    let sources = pump_sources();
    let p = parsed(&sources);
    let c = Corpus::of(&sources, &p);
    for file in PUMP_FILES {
        let lex = lexical::count(&support::production(&support::strip_comments(
            &sources[*file],
        )));
        let s = reads(&c, file);
        println!("{file}: {} (lexical {lex})", s.len());
        for site in s {
            println!("\t{site:?}");
        }
    }
}

/// `file`'s source with `plant` added (a function at its end, or, in the
/// multiplexer, the first statement of a pump step), parsed alone.
fn planted_corpus(file: &str, plant: &str) -> (BTreeMap<String, String>, String) {
    let text = std::fs::read_to_string(repo_root().join(file)).unwrap();
    let body = if file.ends_with("multiplexer.rs") {
        text.replacen(
            "fn check_resolved(raw: &ExecCheckRaw, e: Event) -> (Event, [Option<Event>; 2]) {",
            &format!(
                "fn check_resolved(raw: &ExecCheckRaw, e: Event) -> (Event, [Option<Event>; 2]) {{ {plant};"
            ),
            1,
        )
    } else {
        format!("{text}\nfn planted() {{ {plant}; }}\n")
    };
    assert_ne!(body, text, "{plant} planted in {file}");
    let mut m = BTreeMap::new();
    m.insert(file.to_string(), body.clone());
    (m, body)
}

/// Each spelling of a path read by hand, planted in a pump's module (the
/// review of #573's five ordinary spellings among them), fails; so does
/// one more in a listed file, and one in a pump step.
#[test]
fn every_spelling_of_a_path_read_by_hand_fails_the_ratchet() {
    let facts = "crates/nn-linux/src/sensors/exec_facts.rs";
    let image = "crates/nn-linux/src/sensors/exe_identity.rs";
    let steps = "crates/nn-linux/src/sensors/multiplexer.rs";
    for plant in PLANTED_READS.iter().chain(BYPASSED_READS) {
        for file in [facts, image, steps] {
            let (sources, _) = planted_corpus(file, plant);
            let p = parsed(&sources);
            let c = Corpus::of(&sources, &p);
            let v = violations(&c);
            assert!(
                v.iter()
                    .any(|m| m.starts_with(file) && m.contains("a new one")),
                "{plant} in {file}: {v:#?}"
            );
        }
    }
}

/// The spellings planted before lot 1.7a (the lexical scan caught these).
const PLANTED_READS: &[&str] = &[
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
];

/// Lot 1.7a: the spellings that passed the lexical scan — an import under
/// another name (of `std::fs`, of `kernel_roots`, of one of its readers, of
/// `File`, of a C call), the callee in parentheses, a reader held in a
/// variable, passed as a value or as an array's item, the C calls' `64`
/// forms and a path's system call by number.
const BYPASSED_READS: &[&str] = &[
    "use std::fs as f; f::read(p)",
    "use antitamper_bpf::kernel_roots as kr; kr::read(p, 9)",
    "use antitamper_bpf::kernel_roots::read_all; read_all(p)",
    "use std::fs::File as F; F::open(p)",
    "use libc::stat as st; unsafe { st(c.as_ptr(), &mut s) }",
    "(std::fs::metadata)(p)",
    "let f = std::fs::metadata; f(p)",
    "paths.iter().map(std::fs::read_to_string).count()",
    "[std::fs::canonicalize][0](p)",
    "unsafe { libc::stat64(c.as_ptr(), &mut st) }",
    "unsafe { libc::open64(c.as_ptr(), 0) }",
    "unsafe { libc::syscall(libc::SYS_openat2, 0, c.as_ptr(), &how, 24) }",
];

/// The review of #573 (F1): a lock held while a file is read — directly,
/// through a door, through a function of the module that reads, or while
/// waiting on the reader — fails, in a pump's module and in the doors'.
#[test]
fn a_lock_held_across_a_read_fails_the_ratchet() {
    let sources = pump_sources();
    let p = parsed(&sources);
    let c = Corpus::of(&sources, &p);
    assert!(lock_violations(&c).is_empty(), "{:#?}", lock_violations(&c));
    for (file, plant) in PLANTED_LOCKS.iter().chain(BYPASSED_LOCKS) {
        let text = std::fs::read_to_string(repo_root().join(file)).unwrap();
        let mut m = BTreeMap::new();
        m.insert(file.to_string(), format!("{text}\n{plant}\n"));
        let p = parsed(&m);
        let c = Corpus::of(&m, &p);
        let v = lock_violations(&c);
        assert!(
            v.iter()
                .any(|x| x.starts_with(*file)
                    && (x.contains("`planted`") || x.contains("`PLANTED`"))),
            "{plant} in {file}: {v:#?}"
        );
    }
}

/// The locks planted before lot 1.7a (the lexical scan caught these).
const PLANTED_LOCKS: &[(&str, &str)] = &[
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
];

/// Lot 1.7a: the locks that passed the lexical scan — `parking_lot`'s
/// recursive and upgradable guards, a once's initialisation, a reading
/// function passed as a value or called through parentheses under a lock,
/// a lazy `static` whose initialiser reads.
const BYPASSED_LOCKS: &[(&str, &str)] = &[
    (
        "crates/nn-linux/src/sensors/app_image.rs",
        "fn planted(m: &parking_lot::RwLock<u8>, r: &TieRead) { let _g = m.read_recursive(); let _ = read_step(Path::new(\"/proc\"), r); }",
    ),
    (
        "crates/nn-linux/src/sensors/app_image.rs",
        "fn planted(m: &parking_lot::RwLock<u8>, r: &TieRead) { let _g = m.upgradable_read(); let _ = read_step(Path::new(\"/proc\"), r); }",
    ),
    (
        "crates/nn-linux/src/sensors/app_image.rs",
        "fn planted(o: &std::sync::OnceLock<Found>, r: &TieRead) { o.get_or_init(|| read_step(Path::new(\"/proc\"), r)); }",
    ),
    (
        "crates/nn-linux/src/sensors/app_image.rs",
        "fn planted(ps: &[&Path], r: &TieRead) { let _g = PUMP.lock(); let _ = ps.iter().map(|p| (read_step)(p, r)).count(); }",
    ),
    (
        "crates/nn-linux/src/sensors/kmod_exec.rs",
        "fn planted(e: &Event) { let _g = BUILDERS.lock(); let f = builder_exec; let _ = f(Path::new(\"/\"), e); }",
    ),
    (
        "crates/nn-linux/src/sensors/exe_identity.rs",
        "static PLANTED: std::sync::LazyLock<Option<std::fs::Metadata>> = std::sync::LazyLock::new(|| std::fs::metadata(\"/x\").ok());",
    ),
];

/// Lot 1.7a: the spellings above passed the lexical scan, each planted in a
/// copy of a pump's module: no marker more, no lock rule broken.
#[test]
fn the_lexical_scan_missed_the_bypasses() {
    let facts = "crates/nn-linux/src/sensors/exec_facts.rs";
    let text = std::fs::read_to_string(repo_root().join(facts)).unwrap();
    let base = lexical::count(&support::production(&support::strip_comments(&text)));
    for plant in BYPASSED_READS {
        let copy = format!("{text}\nfn planted() {{ {plant}; }}\n");
        let n = lexical::count(&support::production(&support::strip_comments(&copy)));
        assert_eq!(n, base, "the lexical scan saw it: {plant}");
    }
    for (file, plant) in BYPASSED_LOCKS {
        let text = std::fs::read_to_string(repo_root().join(file)).unwrap();
        let mut code = BTreeMap::new();
        code.insert(
            file.to_string(),
            support::production(&support::strip_comments(&format!("{text}\n{plant}\n"))),
        );
        let v = lexical::lock_violations(&code);
        assert!(
            !v.iter().any(|x| x.contains("`planted`")),
            "the lexical scan saw it: {plant}"
        );
    }
}

/// The lexical scan before lot 1.7a, kept only to show the spellings it
/// missed.
mod lexical {
    use std::collections::{BTreeMap, BTreeSet};

    use super::support::matching_brace;
    use super::{DOORS, PUMP_FILES, STEPS};

    /// A path read by itself: the kernel walks it, follows its links, crosses
    /// its mounts and asks each file system on the way. Each spelling counted
    /// once (none is a part of another).
    pub const MARKERS: &[&str] = &[
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

    pub fn count(text: &str) -> usize {
        MARKERS
            .iter()
            .map(|m| text.matches(m).count())
            .sum::<usize>()
            + fs_function_imports(text)
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
    pub fn lock_violations(code: &BTreeMap<String, String>) -> Vec<String> {
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
}
