//! Lot 353 (pre-alpha Phase 3, case X6): the kernel's views — `/proc`,
//! `/sys` and the cgroup2 hierarchy — are read beneath the roots the
//! agent's start anchored (`antitamper_bpf::kernel_roots`), never by a path
//! walk that a mount laid over them can hold; and the rounds that read
//! them run off the runtime's workers. A FUSE mounted over `/sys/fs/cgroup`
//! that never answered held two of the agent's threads in the kernel —
//! the integrity round's read of its own `memory.max`, the kernel-state
//! round's open of the cgroup root — and every thread that looked up the
//! same names behind them: the admin socket stopped answering, the
//! watchdog's stuck recovery restarted an agent that had recorded nothing.
//!
//! 1. **None**, by name: the production code of the security crates
//!    ([`SCAN`]) calls no path API of the standard library or libc — a
//!    free call on its path argument ([`PATH_CALLS`]) or a `Path` method
//!    on its receiver ([`PATH_METHODS`]) — on a path under `/proc` or
//!    `/sys` — `kernel_roots` does (and the readers built on it:
//!    `state_read::read_state`, `mountinfo::read_bytes`). Lot 353 (the
//!    review of #563, F2): a path is under a view when the expression
//!    names a literal under one, a constant whose value is one, a name the
//!    code gives such a path ([`VIEW_NAMES`]: `proc`, `pdir`, `proc_root`…
//!    — a parameter, a field), or a local its function bound to one of
//!    those (`let via = format!("/proc/self/fd/{}", …)`, used lines later)
//!    — within the whole function, not the two lines around the call
//!    (which missed all of the review's examples) — or a parameter a call
//!    in the same file hands such a path (the lab's FUSE over `/proc`:
//!    `held_executors(&init, …)`, `identify(&dir.join("exe"), …)`). And no third-party call
//!    that reads a view by path itself ([`THIRD_PARTY`]: the `procfs`
//!    crate, aya's `nr_cpus`, `Btf::from_sys_fs`, aya's per-CPU values),
//!    nor a per-CPU map's `get`/`set`/`iter` (aya sizes them with
//!    `nr_cpus`): `antitamper_bpf::per_cpu` does.
//! 2. The shared readers go through it ([`ROUTED`]).
//! 3. The integrity round and the kernel-state round run off the runtime's
//!    worker (`off_the_runtime`), and the agent and the watchdog anchor the
//!    views at their start.
//!
//! The scan is lexical (comments blanked, test items and test files left
//! out). Each rule is shown failing on a planted violation.

mod support;

use std::collections::BTreeMap;
use std::path::Path;

use support::{is_test_file, production, repo_root, rs_files, strip_comments};

/// The security crates' sources.
const SCAN: &[&str] = &[
    "crates/nn-core/src",
    "crates/nn-linux/src",
    "agent/src",
    "watchdog/src",
    "crates/nn-admin/src",
    "antitamper-bpf/src",
    "crates/nn-evidence/src",
    "crates/nn-export/src",
];

/// The module that reads the views (its own calls are the reads).
const KERNEL_ROOTS: &str = "antitamper-bpf/src/kernel_roots.rs";

/// The path calls a walk of the mount table makes, as written: their
/// arguments hold the path.
const PATH_CALLS: &[&str] = &[
    "fs::read(",
    "fs::read_to_string(",
    "fs::read_dir(",
    "fs::metadata(",
    "fs::symlink_metadata(",
    "fs::read_link(",
    "fs::canonicalize(",
    "fs::write(",
    "fs::create_dir(",
    "fs::create_dir_all(",
    "fs::remove_dir(",
    "fs::remove_dir_all(",
    "fs::remove_file(",
    "fs::rename(",
    "fs::copy(",
    "fs::hard_link(",
    "fs::set_permissions(",
    "fs::exists(",
    "File::open(",
    "File::create(",
    "File::create_new(",
    // `OpenOptions::new()….open(path)`, and any other `open` method
    ".open(",
    "libc::statfs(",
    "libc::stat(",
    "libc::lstat(",
    "libc::open(",
    "libc::access(",
    "libc::chmod(",
    "libc::chown(",
    "libc::readlink(",
    "libc::opendir(",
    "libc::openat(libc::AT_FDCWD,",
    "libc::statx(libc::AT_FDCWD,",
];

/// The `Path` methods that walk their receiver.
const PATH_METHODS: &[&str] = &[
    ".exists()",
    ".try_exists()",
    ".is_dir()",
    ".is_file()",
    ".is_symlink()",
    ".read_dir()",
    ".metadata()",
    ".symlink_metadata()",
    ".canonicalize()",
    ".read_link()",
];

/// The names the code gives a path under a view — a parameter, a field
/// (`holders(proc: &Path, …)`, `self.proc_root`).
const VIEW_NAMES: &[&str] = &[
    "proc",
    "pdir",
    "proc_pid",
    "task_dir",
    "fd_dir",
    "proc_root",
    "proc_dir",
    "procfs",
    "sys",
    "sysfs",
    "sys_root",
    "cgroup_root",
    "cg_root",
    "cgroup_dir",
    "cg_dir",
];

/// The names an open file goes by (`file.metadata()` is an `fstat`).
const FILE_HANDLES: &[&str] = &["file", "f", "fd", "held", "fb", "dirfd"];

/// The names a `Metadata` or a `FileType` value goes by (`t.is_dir()`).
const VALUE_NAMES: &[&str] = &["t", "ft", "kind", "ty", "m", "meta", "md", "mb", "st"];

/// The readers beneath the anchored roots: what they return is content or
/// a descriptor, never a path to walk.
const READERS: &[&str] = &["kernel_roots::", "state_read::", "mountinfo::read"];

/// Third-party calls that read a view by path themselves.
const THIRD_PARTY: &[(&str, &str)] = &[
    ("procfs::", "the procfs crate walks the /proc mounted now"),
    (
        "nr_cpus()",
        "aya's CPU count reads /sys/devices/system/cpu/possible by path, once per thread",
    ),
    (
        "online_cpus()",
        "aya's online CPUs read /sys/devices/system/cpu/online by path",
    ),
    (
        "env::current_exe()",
        "std's current_exe reads /proc/self/exe by path (the lab's FUSE over /proc held the \
         telemetry probe's round on it): kernel_roots::current_exe",
    ),
    (
        "from_sys_fs(",
        "aya's Btf::from_sys_fs reads /sys/kernel/btf/vmlinux by path",
    ),
    (
        "PerCpuValues",
        "aya's per-CPU values are sized by nr_cpus() (a read of /sys by path)",
    ),
];

/// A literal path under `/proc` or `/sys` (`"/proc/…"`, `"/sys"`).
fn names_a_view(text: &str) -> bool {
    ["\"/proc/", "\"/proc\"", "\"/sys/", "\"/sys\""]
        .iter()
        .any(|p| text.contains(p))
}

/// The constants of `code` whose value is a path under `/proc` or `/sys`.
fn view_constants(code: &BTreeMap<String, String>) -> Vec<String> {
    let mut out = Vec::new();
    for text in code.values() {
        for line in text.lines() {
            let t = line.trim_start();
            let t = t.strip_prefix("pub ").unwrap_or(t);
            let t = t.strip_prefix("pub(crate) ").unwrap_or(t);
            let Some(rest) = t.strip_prefix("const ") else {
                continue;
            };
            let Some((name, value)) = rest.split_once(':') else {
                continue;
            };
            if value.contains("&str") && names_a_view(value) {
                out.push(name.trim().to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Whether `word` occurs in `text` as a whole identifier.
fn has_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(i, _)| {
        let before = text[..i].chars().next_back();
        let after = text[i + word.len()..].chars().next();
        let ident = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
        !ident(before) && !ident(after)
    })
}

/// A literal path under a view, or a constant or a name of one, in `expr`.
fn names_view_path(expr: &str, constants: &[String]) -> bool {
    names_a_view(expr)
        || expr.contains("c\"/proc")
        || expr.contains("c\"/sys")
        || constants.iter().any(|c| has_word(expr, c))
        || VIEW_NAMES.iter().any(|n| has_word(expr, n))
}

/// The bodies of the functions of `code`: (offset, text) — from `fn` to
/// the brace that closes its body (a nested function is in its outer's
/// body too).
fn fn_bodies(code: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    for (at, _) in code.match_indices("fn ") {
        if at > 0 && code.as_bytes()[at - 1].is_ascii_alphanumeric() {
            continue;
        }
        let rest = &code[at..];
        let (Some(brace), semi) = (rest.find('{'), rest.find(';')) else {
            continue;
        };
        if semi.is_some_and(|s| s < brace) {
            continue; // a declaration, a `fn` type
        }
        let end = brace + support::matching_brace(&rest[brace..]);
        out.push((at, &rest[..end.min(rest.len())]));
    }
    out
}

/// The text from `open` (a `(`) to its matching `)`.
fn call_args(text: &str, open: usize) -> &str {
    let mut depth = 0usize;
    for (i, c) in text[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return &text[open..=open + i];
                }
            }
            _ => {}
        }
    }
    &text[open..]
}

/// The receiver of a method called at `dot`: the expression before it
/// (names, `.`, `::`, `&`, and bracketed groups whole).
fn receiver(text: &str, dot: usize) -> &str {
    let b = text.as_bytes();
    let mut depth = 0usize;
    let mut i = dot;
    while i > 0 {
        let c = b[i - 1];
        match c {
            b')' | b']' => depth += 1,
            b'(' | b'[' => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
            }
            _ if depth > 0 => {}
            _ if c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b':' | b'&') => {}
            _ => break,
        }
        i -= 1;
    }
    &text[i..dot]
}

/// A function's name and its parameters' names (`self` for a receiver),
/// from its `fn` to its body.
fn signature(f: &str) -> Option<(String, Vec<String>)> {
    let rest = f.strip_prefix("fn ")?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    let open = rest.find('(')?;
    let args = call_args(rest, open);
    let inner = args.get(1..args.len().saturating_sub(1))?;
    let params = top_level_split(inner)
        .into_iter()
        .map(|p| {
            let p = p.trim();
            let p = p.strip_prefix("mut ").unwrap_or(p);
            let head = p.split(':').next().unwrap_or("").trim();
            if head.ends_with("self") {
                "self".to_string()
            } else {
                head.trim_start_matches("mut ").to_string()
            }
        })
        .collect();
    Some((name, params))
}

/// `text` split at its commas outside brackets.
fn top_level_split(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut from) = (0i32, 0);
    for (i, c) in text.char_indices() {
        match c {
            '(' | '[' | '{' | '<' => depth += 1,
            ')' | ']' | '}' | '>' => depth -= 1,
            ',' if depth == 0 => {
                out.push(&text[from..i]);
                from = i + 1;
            }
            _ => {}
        }
    }
    if !text[from..].trim().is_empty() {
        out.push(&text[from..]);
    }
    out
}

/// Lot 353 (the review of #563, the lab's FUSE over `/proc`): the
/// parameters, by function (its offset), that a call in the same file
/// hands a path under a view — `held_executors(&init, …)` with `let init =
/// proc_root.join("1")`, `identify(&dir.join("exe"), …)` — to a fixpoint:
/// a walk by path of such a parameter is a walk of the view, whatever the
/// parameter is named.
fn view_params(text: &str, constants: &[String]) -> BTreeMap<usize, Vec<String>> {
    let fns: Vec<(usize, &str, String, Vec<String>)> = fn_bodies(text)
        .into_iter()
        .filter_map(|(at, body)| signature(body).map(|(n, p)| (at, body, n, p)))
        .collect();
    let mut out: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    loop {
        let mut grew = false;
        for (_, body, _, _) in &fns {
            let base = fns
                .iter()
                .find(|f| std::ptr::eq(f.1, *body))
                .map_or(0, |f| f.0);
            let mut tainted = constants.to_vec();
            tainted.extend(out.get(&base).cloned().unwrap_or_default());
            tainted.extend(view_locals(body, &tainted));
            for (callee_at, _, name, params) in &fns {
                for pat in [format!("{name}("), format!("{name}::<")] {
                    for (at, _) in body.match_indices(&pat) {
                        let before = body[..at].chars().next_back();
                        if before.is_some_and(|c| c.is_alphanumeric() || c == '_')
                            || body[..at].ends_with("fn ")
                        {
                            continue;
                        }
                        let method = before == Some('.');
                        let Some(open) = body[at..].find('(').map(|o| at + o) else {
                            continue;
                        };
                        let args = call_args(body, open);
                        let inner = args.get(1..args.len().saturating_sub(1)).unwrap_or("");
                        let skip =
                            usize::from(method && params.first().is_some_and(|p| p == "self"));
                        for (i, arg) in top_level_split(inner).into_iter().enumerate() {
                            let Some(param) = params.get(i + skip) else {
                                continue;
                            };
                            if param == "self" || param.is_empty() {
                                continue;
                            }
                            if names_view_path(arg, &tainted) {
                                let e = out.entry(*callee_at).or_default();
                                if !e.contains(param) {
                                    e.push(param.clone());
                                    grew = true;
                                }
                            }
                        }
                    }
                }
            }
        }
        if !grew {
            return out;
        }
    }
}

/// The locals a function body binds to a path under a view (`let NAME =
/// …` naming one, not through a reader), to a fixpoint.
fn view_locals(body: &str, constants: &[String]) -> Vec<String> {
    let mut names: Vec<String> = constants.to_vec();
    let mut out = Vec::new();
    loop {
        let before = out.len();
        for (at, _) in body.match_indices("let ") {
            let rest = &body[at + 4..];
            let rest = rest.strip_prefix("mut ").unwrap_or(rest);
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() || out.contains(&name) {
                continue;
            }
            let Some(eq) = rest.find('=') else { continue };
            let expr = &rest[eq + 1..];
            let expr = &expr[..expr.find(';').unwrap_or(expr.len())];
            if READERS.iter().any(|r| expr.contains(r)) {
                continue; // content or a descriptor
            }
            if names_view_path(expr, &names) {
                names.push(name.clone());
                out.push(name);
            }
        }
        if out.len() == before {
            return out;
        }
    }
}

/// Rule 1's violations in one file's production code: `line: text`.
fn walks(text: &str, constants: &[String]) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let line_of = |at: usize| text[..at].matches('\n').count();
    let mut out = std::collections::BTreeSet::new();
    let mut flag = |at: usize| {
        let n = line_of(at);
        out.insert(format!(
            "{}: {}",
            n + 1,
            lines.get(n).map_or("", |l| l.trim())
        ));
    };
    let params = view_params(text, constants);
    for (base, body) in fn_bodies(text) {
        let mut tainted = constants.to_vec();
        tainted.extend(params.get(&base).cloned().unwrap_or_default());
        tainted.extend(view_locals(body, &tainted));
        for call in PATH_CALLS {
            for (at, _) in body.match_indices(call) {
                let before = &body[at.saturating_sub(16)..at];
                if READERS
                    .iter()
                    .any(|r| before.ends_with(r.trim_end_matches(':')))
                    || READERS.iter().any(|r| before.contains(r))
                {
                    continue;
                }
                let open = at + call.find('(').unwrap_or(call.len() - 1);
                let args = call_args(body, open);
                if names_view_path(args, &tainted) {
                    flag(base + at);
                }
            }
        }
        for method in PATH_METHODS {
            for (at, _) in body.match_indices(method) {
                let rcv = receiver(body, at);
                // an open file's own metadata asks no path (`fstat`)
                let last = rcv.rsplit(['.', ':', '&']).next().unwrap_or(rcv);
                if *method == ".metadata()" && FILE_HANDLES.contains(&last) {
                    continue;
                }
                // a `Metadata` or a `FileType` asks nothing either
                if rcv.chars().all(|c| c.is_alphanumeric() || c == '_')
                    && VALUE_NAMES.contains(&rcv)
                {
                    continue;
                }
                if names_view_path(rcv, &tainted) {
                    flag(base + at);
                }
            }
        }
    }
    for (call, _) in THIRD_PARTY {
        for (at, _) in text.match_indices(call) {
            flag(at);
        }
    }
    let per_cpu = per_cpu_names(text);
    for (name, _) in &per_cpu {
        for m in [".get(", ".set(", ".iter("] {
            let pat = format!("{name}{m}");
            for (at, _) in text.match_indices(&pat) {
                let whole = at == 0 || {
                    let c = text.as_bytes()[at - 1];
                    !(c.is_ascii_alphanumeric() || c == b'_')
                };
                // the name's nearest declaration before the use is a
                // per-CPU map's (a parameter of the same name may be
                // another map's)
                let nearest = declarations(text, name)
                    .into_iter()
                    .filter(|(d, _)| *d < at)
                    .max_by_key(|(d, _)| *d);
                if whole && nearest.is_some_and(|(_, per)| per) {
                    flag(at);
                }
            }
        }
    }
    out.into_iter().collect()
}

/// Where `text` declares `name` with a type (`name: T`), and whether `T`
/// is an aya per-CPU map (or an alias of one).
fn declarations(text: &str, name: &str) -> Vec<(usize, bool)> {
    let aliases: Vec<&str> = per_cpu_types(text);
    let mut out = Vec::new();
    for (at, _) in text.match_indices(&format!("{name}:")) {
        let whole = at == 0 || {
            let c = text.as_bytes()[at - 1];
            !(c.is_ascii_alphanumeric() || c == b'_' || c == b':')
        };
        if !whole || text[at + name.len()..].starts_with("::") {
            continue;
        }
        let ty = &text[at + name.len() + 1..];
        let ty = &ty[..ty.find([',', ')', '{', ';', '=']).unwrap_or(ty.len())];
        // a type (`PerCpuArray<…>`) or a struct literal's value
        // (`PerCpuArray::try_from(…)`)
        let per = aliases.iter().any(|a| ty.contains(a.trim_end_matches('<')));
        out.push((at, per));
    }
    out
}

/// The aya per-CPU map types `text` names, its aliases of them included.
fn per_cpu_types(text: &str) -> Vec<&str> {
    let mut types = vec!["PerCpuArray<", "PerCpuHashMap<"];
    for line in text.lines() {
        let t = line.trim_start();
        if let Some(rest) = t
            .strip_prefix("type ")
            .or_else(|| t.strip_prefix("pub type "))
        {
            if rest.contains("PerCpuArray<") || rest.contains("PerCpuHashMap<") {
                if let Some((name, _)) = rest.split_once('=') {
                    types.push(name.trim());
                }
            }
        }
    }
    types
}

/// The names `text` declares as aya per-CPU maps (`name: PerCpuArray<…>`,
/// `name: &PerCpuArray<…>`, and a type alias of one), each with where.
fn per_cpu_names(text: &str) -> Vec<(String, usize)> {
    let types = per_cpu_types(text);
    let mut out: Vec<(String, usize)> = Vec::new();
    for ty in &types {
        for (at, _) in text.match_indices(ty) {
            let before = text[..at].trim_end();
            let before = before.strip_suffix('&').unwrap_or(before).trim_end();
            let Some(before) = before.strip_suffix(':') else {
                continue;
            };
            let name: String = before
                .chars()
                .rev()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            if !name.is_empty() && !out.iter().any(|(n, _)| *n == name) {
                out.push((name, at));
            }
        }
    }
    out
}

/// The production code of every file of [`SCAN`], by path.
fn scan_code(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for dir in SCAN {
        let mut files = Vec::new();
        rs_files(&root.join(dir), &mut files);
        for f in files {
            let rel = f
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if is_test_file(&rel) || test_module(&f) {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap_or_else(|e| panic!("{rel}: {e}"));
            out.insert(rel, production(&strip_comments(&text)));
        }
    }
    out
}

/// Whether the module of the file `f` is declared under `#[cfg(test)]` in
/// its parent (`#[cfg(test)] mod golden;`): test code in a file of its own.
fn test_module(f: &Path) -> bool {
    let (Some(dir), Some(stem)) = (f.parent(), f.file_stem()) else {
        return false;
    };
    let stem = stem.to_string_lossy();
    let mut parents = vec![dir.join("mod.rs"), dir.join("lib.rs"), dir.join("main.rs")];
    if let (Some(up), Some(n)) = (dir.parent(), dir.file_name()) {
        parents.push(up.join(format!("{}.rs", n.to_string_lossy())));
    }
    let decl = format!("mod {stem};");
    parents.iter().any(|p| {
        let Ok(text) = std::fs::read_to_string(p) else {
            return false;
        };
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        lines.windows(2).any(|w| {
            w[0].starts_with("#[cfg(test)]")
                && (w[1] == decl
                    || w[1] == format!("pub mod {stem};")
                    || w[1] == format!("pub(crate) mod {stem};"))
        })
    })
}

/// The constants that name bpffs (`/sys/fs/bpf`: its pins are opened by
/// path through the bpf(2) object calls, a file system of its own the
/// integrity round watches — `PROTECTED_MOUNT_PREFIXES`, `MOUNT_WATCHED`)
/// and the kernel's BTF directory's watch: not views read here.
const NOT_VIEWS: &[&str] = &[
    "BPFFS_MOUNT",
    "BPFFS_ROOT",
    "DEFAULT_BPFFS_ROOT",
    "PIN_DIR",
    "PIN_ROOT",
    "UNIT",
];

/// The files whose walks by path stay, how many, and why: each takes the
/// anchored root when its process has one and walks only where none was
/// anchored (a test binary).
const KNOWN: &[(&str, usize, &str)] = &[
    (
        "crates/nn-linux/src/sandbox/mod.rs",
        1,
        "a forked child's allocation-free count of its own threads: beneath the /proc root the \
         process anchored (`kernel_roots::proc_root_fd`, openat), by path only in a process \
         that anchored none",
    ),
    (
        "crates/nn-linux/src/worker/spawn.rs",
        1,
        "a forked worker's allocation-free write of its own oom_score_adj: beneath the /proc \
         root the core anchored, by path only in a process that anchored none",
    ),
    (
        "crates/nn-admin/src/cli.rs",
        2,
        "`policy test`'s fake process tree: a temporary directory it names proc_root, made \
         and removed — never the kernel's /proc",
    ),
    (
        "crates/nn-linux/src/response/quarantine.rs",
        3,
        "`record_in_place`'s read and atomic rewrite of the vault entry \
         (`<quarantine_dir>/vault/<id>.meta`, the agent's own state): the same-file taint \
         reaches it through a caller that also holds the held binary's `/proc` path — no view",
    ),
    (
        "crates/nn-linux/src/verifier_check.rs",
        3,
        "the verifier gate (a lab build's --verifier-check, a process of its own, never the \
         agent's run): its kprobe instance created in tracefs, its `kprobe_events` appended",
    ),
];

#[test]
fn no_kernel_view_is_walked_by_path() {
    let code = scan_code(&repo_root());
    assert!(code.len() > 300, "scanned {} files", code.len());
    let constants: Vec<String> = view_constants(&code)
        .into_iter()
        .filter(|c| !NOT_VIEWS.contains(&c.as_str()))
        .collect();
    assert!(
        constants.iter().any(|c| c == "MOUNTINFO_HOST"),
        "the scan finds the view constants: {constants:?}"
    );
    let mut found = Vec::new();
    for (f, text) in code.iter().filter(|(f, _)| f.as_str() != KERNEL_ROOTS) {
        let w = walks(text, &constants);
        match KNOWN.iter().find(|(k, _, _)| k == f) {
            Some((_, n, _)) if w.len() == *n => {}
            Some((_, n, _)) => found.push(format!(
                "{f}: {} walks, {n} known (lower the pin when one goes): {w:?}",
                w.len()
            )),
            None => found.extend(w.into_iter().map(|l| format!("{f}:{l}"))),
        }
    }
    for (k, _, _) in KNOWN {
        assert!(
            code.contains_key(*k),
            "{k}: listed in KNOWN, not in the scan"
        );
    }
    assert!(
        found.is_empty(),
        "a path under /proc or /sys walked by path — a mount laid over the view holds it: read \
         it with antitamper_bpf::kernel_roots (read, read_to_string, read_dir, metadata, \
         read_link, open, write, create_dir, chmod_fd, reopen_fd, vmlinux_btf…), \
         state_read::read_state, or antitamper_bpf::per_cpu for a per-CPU map:\n{}",
        found.join("\n")
    );
}

/// Rule 1 fails on a planted walk: a literal, a `format!`, a constant —
/// and (lot 353, the review of #563, F2) each of the review's examples,
/// which the two-line window missed: a parameter named for its view, a
/// local bound lines before its use, a call the list lacked, a
/// third-party read, a per-CPU map's read.
#[test]
fn a_planted_walk_of_a_view_is_found() {
    let constants = vec!["TAINTED".to_string()];
    let in_fn = |body: &str| format!("fn f() {{\n{body}\n}}\n");
    for (planted, why) in [
        (
            in_fn("let x = std::fs::read_to_string(\"/proc/meminfo\");"),
            "a literal",
        ),
        (
            in_fn("let x = std::fs::read(\n    format!(\"/proc/{pid}/stat\"),\n);"),
            "a format! on the next line",
        ),
        (
            in_fn("let ok = Path::new(\"/sys/kernel/btf/vmlinux\").exists();"),
            "exists",
        ),
        (in_fn("let t = fs::read_to_string(TAINTED);"), "a constant"),
        (
            in_fn("let f = File::open(format!(\"/sys/fs/cgroup{cg}/memory.max\"));"),
            "the cgroup tree",
        ),
        // the review's examples
        (
            "fn holders_by(proc: &Path, id: u32) -> Vec<Holder> {\n    let Ok(dir) = \
             std::fs::read_dir(proc) else {\n        return Vec::new();\n    };\n    \
             Vec::new()\n}\n"
                .to_string(),
            "known_system_prog: read_dir of a parameter named for /proc",
        ),
        (
            "fn held_link(pdir: &Path) -> Option<u32> {\n    let fds = \
             std::fs::read_dir(pdir.join(\"fd\")).ok()?;\n    None\n}\n"
                .to_string(),
            "known_system_prog: read_dir below such a parameter",
        ),
        (
            in_fn(
                "match fs::set_permissions(format!(\"/proc/self/fd/{}\", f.as_raw_fd()), m) {\n\
                 Ok(()) => {}\nErr(e) => return Err(e),\n}",
            ),
            "socket_watch: set_permissions, a call the list lacked",
        ),
        (
            in_fn(
                "let via = format!(\"/proc/self/fd/{}\", held.as_raw_fd());\nlet a = 1;\nlet \
                 b = 2;\nlet c = 3;\nlet now = fs::read(&via)?;",
            ),
            "quarantine: a local bound lines before its use",
        ),
        (
            in_fn("let mut w = OpenOptions::new()\n.write(true)\n.custom_flags(0)\n.open(&via)?;")
                .replace("fn f() {", "fn f(via: &str) {\nlet via = format!(\"/proc/x{via}\");"),
            "quarantine: OpenOptions…open of such a local",
        ),
        (
            "fn exe(&self, tgid: u32) -> PathBuf {\n    \
             std::fs::read_link(self.proc_root.join(tgid.to_string()).join(\"exe\")).unwrap()\n}\n"
                .to_string(),
            "a field named for /proc",
        ),
        (
            "fn live_under(root: &Path, proc_root: &Path) {\n    let init = proc_root.join(\"1\");\n    \
             let held = held_executors(&init, root);\n}\nfn held_executors(pid: &Path, root: &Path) \
             -> Vec<u64> {\n    let Ok(fds) = std::fs::read_dir(pid.join(\"fd\")) else {\n        \
             return Vec::new();\n    };\n    Vec::new()\n}\n"
                .to_string(),
            "the lab: a parameter handed a view path by a caller in the file (any name)",
        ),
        (
            "fn keep(proc_root: &Path) {\n    let dir = proc_root.join(pid.to_string());\n    \
             let _ = identify(&dir.join(\"exe\"), None);\n}\nfn identify(path: &Path, e: Option<u8>) \
             -> u8 {\n    let file = std::fs::File::open(path);\n    0\n}\n"
                .to_string(),
            "the lab: a by-path open of /proc/<pid>/exe in a callee",
        ),
        (
            in_fn("let p = procfs::process::all_processes();"),
            "kill: the procfs crate",
        ),
        (
            in_fn("let n = aya::util::nr_cpus();"),
            "aya's per-thread CPU count",
        ),
        (
            in_fn("let btf = Btf::from_sys_fs()?;"),
            "aya's BTF read by path",
        ),
        (
            "struct M {\n    counters: PerCpuArray<MapData, u64>,\n}\nfn f(m: &M) -> u64 {\n    \
             m.counters.get(&0, 0).unwrap().iter().sum()\n}\n"
                .to_string(),
            "a per-CPU map's get (aya's nr_cpus)",
        ),
        (
            "fn read(map: &PerCpuArray<MapData, u64>) -> u64 {\n    map.get(&1, 0).unwrap()[0]\n}\n"
                .to_string(),
            "a per-CPU map parameter's get",
        ),
        (
            "struct M {\n    pub counters: PerCpuArray<MapData, u64>,\n}\nfn new(t: Map) -> M {\n    \
             M { counters: PerCpuArray::try_from(t).unwrap() }\n}\nfn sum(&self) -> u64 {\n    \
             self.counters.get(&(i as u32), 0).unwrap().iter().sum()\n}\n"
                .to_string(),
            "a field set by a struct literal, read in another method",
        ),
    ] {
        assert!(!walks(&planted, &constants).is_empty(), "{why}: {planted}");
    }
    for clean in [
        in_fn("let x = antitamper_bpf::kernel_roots::read_to_string(\"/proc/meminfo\");"),
        in_fn("let x = std::fs::read_to_string(\"/etc/os-release\");"),
        in_fn("let t = fs::read_to_string(TAINTED_NOT);"),
        in_fn("let names = antitamper_bpf::kernel_roots::read_dir(\"/proc\");"),
        "fn g(f: &File) -> u64 {\n    f.metadata().unwrap().len()\n}\n".to_string(),
        in_fn("let at = kernel_roots::open(\"/proc/x\", libc::O_PATH)?;\nlet m = at.metadata()?;"),
        in_fn("let v = antitamper_bpf::per_cpu::sum(&self.counters, 0);"),
        "fn process(p: &Path) {\n    let _ = std::fs::read(p);\n}\n".to_string(),
    ] {
        assert!(walks(&clean, &constants).is_empty(), "{clean}");
    }
    let code = BTreeMap::from([(
        "x.rs".to_string(),
        "pub const TAINTED: &str = \"/proc/sys/kernel/tainted\";\nconst N: u32 = 1;".to_string(),
    )]);
    assert_eq!(view_constants(&code), vec!["TAINTED".to_string()]);
}

/// The shared readers and the function each one's body must read through.
const ROUTED: &[(&str, &str, &str)] = &[
    (
        "crates/nn-linux/src/state_read.rs",
        "pub fn read_bounded(",
        "kernel_roots::read(",
    ),
    (
        "crates/nn-linux/src/state_read.rs",
        "pub fn read_file_bounded(",
        "kernel_roots::read_file_bounded(",
    ),
    (
        "crates/nn-linux/src/mountinfo.rs",
        "pub fn read_bytes(",
        "kernel_roots::read(",
    ),
    (
        "crates/nn-linux/src/own_cpus.rs",
        "pub fn open_source(",
        "kernel_roots::open(",
    ),
    (
        "crates/nn-linux/src/sysctl_cgroup.rs",
        "fn open_root_cgroup(",
        "kernel_roots::cgroup_root(",
    ),
    (
        "antitamper-bpf/src/config_read.rs",
        "pub fn read_config(",
        "kernel_roots::open(",
    ),
    (
        "antitamper-bpf/src/cgroup_guard.rs",
        "fn is_cgroup2(",
        "kernel_roots::open(",
    ),
];

/// The body of the function that starts at `head` in `code` (to its first
/// line that closes at column 0).
fn body<'a>(code: &'a str, rel: &str, head: &str) -> &'a str {
    let at = code
        .find(head)
        .unwrap_or_else(|| panic!("{rel}: `{head}` not found"));
    let rest = &code[at..];
    let end = rest.find("\n}\n").map_or(rest.len(), |i| i + 3);
    &rest[..end]
}

#[test]
fn the_shared_readers_read_beneath_the_anchored_roots() {
    let root = repo_root();
    for (rel, head, call) in ROUTED {
        let text = production(&strip_comments(
            &std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}")),
        ));
        let b = body(&text, rel, head);
        assert!(
            b.contains(call),
            "{rel}: `{head}` does not read through `{call}`:\n{b}"
        );
    }
}

/// The rounds that read the views, each run off the runtime's worker, and
/// the starts that anchor them.
const OFF_THE_RUNTIME: &[(&str, &str, &[&str])] = &[
    (
        "crates/nn-linux/src/self_integrity.rs",
        "tokio::time::sleep(Duration::from_secs(15)).await;",
        &[
            "off_the_runtime(|| checker.round(true))",
            "off_the_runtime(|| checker.round(false))",
        ],
    ),
    (
        "crates/nn-linux/src/kernel_state.rs",
        "pub fn spawn(",
        &[
            "off_the_runtime(||",
            "round(&mut w, Path::new(\"/\"), &known)",
        ],
    ),
    (
        "agent/src/boot/mod.rs",
        "forbid_core_dumps();",
        &["kernel_roots::init()"],
    ),
    (
        "watchdog/src/main.rs",
        "\"watchdog starting\"",
        &["kernel_roots::init()"],
    ),
];

#[test]
fn the_rounds_run_off_the_runtime_and_the_starts_anchor_the_views() {
    let root = repo_root();
    for (rel, head, calls) in OFF_THE_RUNTIME {
        let text = strip_comments(
            &std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}")),
        );
        let at = text
            .find(head)
            .unwrap_or_else(|| panic!("{rel}: `{head}` not found"));
        let window: String = text[at..].lines().take(60).collect::<Vec<_>>().join("\n");
        for call in *calls {
            assert!(
                window.contains(call),
                "{rel}: `{call}` not within 60 lines of `{head}`"
            );
        }
    }
    // the kernel-state round's reads are inside the closure, not before it
    let ks = strip_comments(
        &std::fs::read_to_string(root.join("crates/nn-linux/src/kernel_state.rs")).unwrap(),
    );
    let spawn = &ks[ks.find("pub fn spawn(").unwrap()..];
    let off = spawn.find("off_the_runtime(||").unwrap();
    let round = spawn.find("round(&mut w, Path::new(\"/\")").unwrap();
    assert!(
        off < round,
        "the kernel-state round runs inside off_the_runtime"
    );
}

/// Lot 353 (the lab's round on 6.12): `std::thread::available_parallelism`
/// reads the cgroup's `cpu.max` by path (`/sys/fs/cgroup/<cgroup>/…`) — a
/// FUSE mounted over `/sys/fs/cgroup` held the thread that asked. The
/// production code counts CPUs with `kernel_roots::available_parallelism`
/// (or the affinity); the one call left is the non-Linux branch of the
/// audit log's parallel check.
#[test]
fn no_cpu_count_walks_the_cgroup_tree() {
    let code = scan_code(&repo_root());
    let mut found: BTreeMap<&str, usize> = BTreeMap::new();
    for (f, text) in &code {
        let n = text.matches("std::thread::available_parallelism").count()
            + text
                .matches("thread::available_parallelism()")
                .count()
                .saturating_sub(text.matches("std::thread::available_parallelism()").count());
        if n > 0 {
            found.insert(f.as_str(), n);
        }
    }
    assert_eq!(
        found,
        BTreeMap::from([("agent/src/config/overlay_floor.rs", 1)]),
        "std's CPU count walks /sys/fs/cgroup by path: use \
         antitamper_bpf::kernel_roots::available_parallelism"
    );
    let ov = strip_comments(
        &std::fs::read_to_string(repo_root().join("agent/src/config/overlay_floor.rs")).unwrap(),
    );
    let at = ov.find("std::thread::available_parallelism").unwrap();
    assert!(
        ov[..at]
            .rfind("#[cfg(not(target_os = \"linux\"))]")
            .is_some_and(|c| at - c < 200 && ov[c..at].matches('{').count() == 1),
        "the one call is the non-Linux branch"
    );
}
