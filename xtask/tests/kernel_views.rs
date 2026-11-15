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
    // lot 353 (re-check 1 of #563, N2 C): the `*at` calls, whatever their
    // directory — an absolute path ignores it (`fstatat(AT_FDCWD,
    // c"/proc/1", …)`)
    "libc::openat(",
    "libc::statx(",
    "libc::fstatat(",
    "libc::fstatat64(",
    "libc::faccessat(",
    "libc::readlinkat(",
    "libc::fchmodat(",
    "libc::fchownat(",
    "libc::mkdirat(",
    "libc::unlinkat(",
    "libc::renameat(",
    "libc::linkat(",
    "libc::utimensat(",
    "libc::name_to_handle_at(",
    // lot 353 (re-check 2 of #563, plant M): an exec resolves its program
    // by path — `Command::new("/proc/self/exe")` (the start's self-test),
    // `Command::new("/proc/self/fd/N")` (a worker's image) walk the `/proc`
    // mounted now, in the child, while the spawner waits for the exec
    "Command::new(",
    "libc::execv(",
    "libc::execve(",
    "libc::execvp(",
    "libc::execveat(",
    // and the by-path calls the responses use on the host's view
    "libc::removexattr(",
    "libc::lremovexattr(",
    "libc::setxattr(",
    "libc::lsetxattr(",
    "libc::getxattr(",
    "libc::lgetxattr(",
    "libc::unlink(",
    "libc::rmdir(",
    "libc::mkdir(",
    "libc::rename(",
    "libc::truncate(",
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
/// Lot 353 (re-check 1 of #563, N2 D): or holds one — a slice of them
/// (`&[&str]`, `&[(&str, …)]`), its item written over several lines — and
/// the `static`s alike.
fn view_constants(code: &BTreeMap<String, String>) -> Vec<String> {
    let mut out = Vec::new();
    for text in code.values() {
        for (at, _) in text
            .match_indices("const ")
            .chain(text.match_indices("static "))
        {
            let before = text[..at].chars().next_back();
            if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                continue;
            }
            let rest = &text[at..];
            let rest = rest.split_once(' ').map_or(rest, |(_, r)| r);
            let rest = rest.strip_prefix("mut ").unwrap_or(rest);
            let Some((name, value)) = rest.split_once(':') else {
                continue;
            };
            let name = name.trim();
            if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                continue;
            }
            let item = &value[..item_end(value)];
            if item.contains("&str") && names_a_view(item) {
                out.push(name.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Where the item `text` starts ends: its `;` outside brackets.
fn item_end(text: &str) -> usize {
    let mut depth = 0i32;
    for (i, c) in text.char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth < 0 {
                    return i;
                }
            }
            ';' if depth == 0 => return i,
            _ => {}
        }
    }
    text.len()
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
        || constants.iter().any(|c| {
            // a method returning a view path (`.exec_path(`): its call
            if c.starts_with('.') {
                expr.contains(c.as_str())
            } else {
                has_word(expr, c)
            }
        })
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
        // lot 353 (re-check 2 of #563): the body's `{` or the declaration's
        // `;` outside brackets — a `;` in an array type of the signature
        // (`-> Option<(String, [u8; 32])>`, `ProcFacts::trusted_exe`) is
        // neither, and the function was never scanned
        let mut depth = 0i32;
        let mut head_end = None;
        for (i, c) in rest.char_indices() {
            match c {
                '(' | '[' => depth += 1,
                ')' | ']' => depth -= 1,
                '{' if depth == 0 => {
                    head_end = Some((i, false));
                    break;
                }
                ';' if depth == 0 => {
                    head_end = Some((i, true));
                    break;
                }
                _ => {}
            }
        }
        let Some((brace, false)) = head_end else {
            continue; // a declaration, a `fn` type
        };
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
fn view_params(
    text: &str,
    constants: &[String],
    seed: &BTreeMap<usize, Vec<String>>,
) -> BTreeMap<usize, Vec<String>> {
    let fns: Vec<(usize, &str, String, Vec<String>)> = fn_bodies(text)
        .into_iter()
        .filter_map(|(at, body)| signature(body).map(|(n, p)| (at, body, n, p)))
        .collect();
    let mut out: BTreeMap<usize, Vec<String>> = seed.clone();
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
            let scopes = scope_taint(body, &tainted);
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
                            let in_scope = scopes
                                .iter()
                                .any(|(span, t)| span.contains(&at) && names_view_path(arg, t));
                            if names_view_path(arg, &tainted) || in_scope {
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

/// Lot 353 (re-check 1 of #563, N2 D): the names `body` binds to the items
/// of an expression naming a view path (one of `names`, a literal), each
/// with where they are bound: a `for` loop's pattern (its body), and the
/// parameters of the closures of the statement that iterates it
/// (`.iter()`, `.into_iter()`: that statement).
fn iterated(body: &str, names: &[String]) -> Vec<(std::ops::Range<usize>, Vec<String>)> {
    let idents = |pat: &str| -> Vec<String> {
        pat.split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .filter(|w| !w.is_empty() && *w != "mut" && *w != "ref" && *w != "_")
            .filter(|w| {
                w.chars()
                    .next()
                    .is_some_and(|c| c.is_lowercase() || c == '_')
            })
            .map(str::to_string)
            .collect()
    };
    let mut out = Vec::new();
    for (at, _) in body.match_indices("for ") {
        if body[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
        {
            continue;
        }
        let rest = &body[at + 4..];
        let Some(inn) = rest.find(" in ") else {
            continue;
        };
        let Some(brace) = rest[inn..].find('{').map(|b| inn + b) else {
            continue;
        };
        if names_view_path(&rest[inn + 4..brace], names) {
            let open = at + 4 + brace;
            let end = open + support::matching_brace(&body[open..]);
            out.push((open..end, idents(&rest[..inn])));
        }
    }
    for it in [".iter()", ".into_iter()"] {
        for (at, _) in body.match_indices(it) {
            let rcv = receiver(body, at);
            if rcv.is_empty() || !names_view_path(rcv, names) {
                continue;
            }
            let end = at + item_end(&body[at..]);
            let params: Vec<String> = closure_params(&body[at..end])
                .iter()
                .flat_map(|p| idents(p))
                .collect();
            if !params.is_empty() {
                out.push((at..end, params));
            }
        }
    }
    out
}

/// Each scope of [`iterated`] with what is tainted in it: `tainted`, the
/// names it binds to the items, and the locals it binds from those.
fn scope_taint(body: &str, tainted: &[String]) -> Vec<(std::ops::Range<usize>, Vec<String>)> {
    iterated(body, tainted)
        .into_iter()
        .map(|(span, names)| {
            let mut t = tainted.to_vec();
            t.extend(names);
            let locals = view_locals(&body[span.clone()], &t);
            t.extend(locals);
            (span, t)
        })
        .collect()
}

/// The `(` of the call `at` is an argument of: the nearest unmatched one
/// before it, within its statement.
fn enclosing_open(text: &str, at: usize) -> Option<usize> {
    let b = text.as_bytes();
    let mut depth = 0usize;
    let mut i = at;
    while i > 0 {
        i -= 1;
        match b[i] {
            b')' | b']' => depth += 1,
            b'(' | b'[' if depth > 0 => depth -= 1,
            b'(' => return Some(i),
            b'[' => return None,
            b';' | b'{' | b'}' if depth == 0 => return None,
            _ => {}
        }
    }
    None
}

/// The name of the function called at the `(` `open` (`libc::openat`,
/// `open_dir`, `File::open`).
fn callee(text: &str, open: usize) -> &str {
    let start = text[..open]
        .rfind(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':' || c == '.'))
        .map_or(0, |i| i + 1);
    &text[start..open]
}

/// The module name of the file `f` (`mod.rs`: its directory's).
fn module_of(f: &str) -> String {
    let stem = Path::new(f)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    if stem == "mod" {
        Path::new(f)
            .parent()
            .and_then(Path::file_name)
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        stem
    }
}

/// The view constants of the file `f`: `constants`, and the functions that
/// return a view path — by their name in their own file, by their module
/// path elsewhere (`response::host_path`: another file's `host_path` is
/// not it).
fn constants_of(f: &str, constants: &[String], returning: &[(String, String)]) -> Vec<String> {
    let mut out = constants.to_vec();
    for (rf, name) in returning {
        if NOT_VIEWS.contains(&name.as_str()) {
            continue;
        }
        // lot 353 (re-check 2 of #563): a method (`SelfImage::exec_path`)
        // by its call, in any file
        if let Some(m) = name.strip_prefix('.') {
            out.push(format!(".{m}("));
            continue;
        }
        out.push(if rf == f {
            name.clone()
        } else {
            format!("{}::{name}", module_of(rf))
        });
    }
    out
}

/// A `pub fn` another file may call: its file, offset and parameters.
type Callee = (String, usize, Vec<String>);

/// Lot 353 (re-check 1 of #563, N2 A): the parameters, by file and by
/// function offset, that a call in another file hands a path under a view
/// — `crate::host_hardening::stat_it(Path::new("/proc/1/status"))` taints
/// `stat_it`'s parameter in `host_hardening.rs`. A call is matched by its
/// module path's last segment and the function's name (a `pub fn` of the
/// file of that module); what it hands over is a literal under a view or
/// a constant of one (a parameter named `proc` is the callee file's own).
fn cross_file_params(
    code: &BTreeMap<String, String>,
    constants: &[String],
) -> BTreeMap<String, BTreeMap<usize, Vec<String>>> {
    // (module, function) -> (file, offset, parameters)
    let mut public: BTreeMap<(String, String), Vec<Callee>> = BTreeMap::new();
    for (f, text) in code {
        let module = module_of(f);
        for (at, body) in fn_bodies(text) {
            let head = text[..at].trim_end();
            if !(head.ends_with("pub") || head.ends_with("pub(crate)")) {
                continue;
            }
            if let Some((name, params)) = signature(body) {
                public
                    .entry((module.clone(), name))
                    .or_default()
                    .push((f.clone(), at, params));
            }
        }
    }
    let mut out: BTreeMap<String, BTreeMap<usize, Vec<String>>> = BTreeMap::new();
    // a literal or a constant handed over — or an item of a list of them,
    // a parameter the file's own calls hand one, a local bound to those:
    // the names the code gives a path (`proc`, `sys`) are the callee
    // file's own business
    let hands_a_view = |arg: &str, tainted: &[String]| {
        names_a_view(arg)
            || arg.contains("c\"/proc")
            || arg.contains("c\"/sys")
            || tainted.iter().any(|c| has_word(arg, c))
    };
    let strict = |t: Vec<String>| -> Vec<String> {
        t.into_iter()
            .filter(|n| !VIEW_NAMES.contains(&n.as_str()))
            .collect()
    };
    {
        for text in code.values() {
            let params = view_params(text, constants, &BTreeMap::new());
            let imported = imports(text);
            // re-check 2 of #563: a field set to a view path, handed on
            // (`cgroup_join::started_in_cgroup(&self.root, pid)`)
            let fields = view_fields(text, constants, &params);
            for (base, body) in fn_bodies(text) {
                let mut tainted = constants.to_vec();
                tainted.extend(fields.iter().cloned());
                tainted.extend(strict(params.get(&base).cloned().unwrap_or_default()));
                tainted.extend(strict(view_locals(body, &tainted)));
                let scopes: Vec<_> = scope_taint(body, &tainted)
                    .into_iter()
                    .map(|(span, t)| (span, strict(t)))
                    .collect();
                // `module::name(`, and (re-check 2 of #563, plant E) a
                // bare `name(` the file imports (`use crate::m::name;`)
                let mut calls: Vec<(usize, String, String)> = Vec::new();
                for (at, _) in body.match_indices("::") {
                    let rest = &body[at + 2..];
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if !rest[name.len()..].starts_with('(') {
                        continue;
                    }
                    let module: String = body[..at]
                        .chars()
                        .rev()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect();
                    calls.push((at + 2 + name.len(), module, name));
                }
                for (name, module) in &imported {
                    for (at, _) in body.match_indices(&format!("{name}(")) {
                        let before = body[..at].chars().next_back();
                        if before.is_some_and(|c| {
                            c.is_alphanumeric() || c == '_' || c == ':' || c == '.'
                        }) || body[..at].ends_with("fn ")
                        {
                            continue;
                        }
                        calls.push((at + name.len(), module.clone(), name.clone()));
                    }
                }
                for (open, module, name) in calls {
                    let at = open;
                    let Some(callees) = public.get(&(module, name.clone())) else {
                        continue;
                    };
                    let args = call_args(body, open);
                    let inner = args.get(1..args.len().saturating_sub(1)).unwrap_or("");
                    for (i, arg) in top_level_split(inner).into_iter().enumerate() {
                        let scoped = scopes
                            .iter()
                            .any(|(span, t)| span.contains(&at) && hands_a_view(arg, t));
                        if !hands_a_view(arg, &tainted) && !scoped {
                            continue;
                        }
                        for (cf, cat, cparams) in callees {
                            let Some(param) = cparams.get(i).filter(|p| *p != "self") else {
                                continue;
                            };
                            let e = out.entry(cf.clone()).or_default().entry(*cat).or_default();
                            if !e.contains(param) {
                                e.push(param.clone());
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// Lot 353 (re-check 2 of #563, plant E): the functions `text` imports by
/// name (`use crate::host_hardening::stat_it;`, `use super::m::{a, b};`),
/// each with its module (the path's last segment before it).
fn imports(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim_start();
        let Some(rest) = t
            .strip_prefix("use ")
            .or_else(|| t.strip_prefix("pub use "))
        else {
            continue;
        };
        let rest = rest.trim_end().trim_end_matches(';');
        let (path, names): (&str, Vec<&str>) = match rest.split_once("::{") {
            Some((p, n)) => (
                p,
                n.trim_end_matches('}').split(',').map(str::trim).collect(),
            ),
            None => match rest.rsplit_once("::") {
                Some((p, n)) => (p, vec![n.trim()]),
                None => continue,
            },
        };
        let module = path.rsplit("::").next().unwrap_or(path).to_string();
        for n in names {
            let n = n.split(" as ").next().unwrap_or(n).trim();
            if !n.is_empty()
                && n.chars().all(|c| c.is_alphanumeric() || c == '_')
                && n.chars().next().is_some_and(|c| c.is_lowercase())
            {
                out.push((n.to_string(), module.clone()));
            }
        }
    }
    out
}

/// Lot 353 (re-check 1 of #563, N3): the functions of `code` that return a
/// path under a view (`fn host_root() -> PathBuf { … PathBuf::from(
/// "/proc/1/root") … }`, a literal outside a reader's call): a walk by
/// path of what they return is a walk of the view. The path is one the
/// function builds (`PathBuf::from`, `Path::new` of a view literal).
fn view_returning_fns(code: &BTreeMap<String, String>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (f, text) in code {
        if f == KERNEL_ROOTS {
            continue; // its own reads
        }
        for (_, body) in fn_bodies(text) {
            let Some(brace) = body.find('{') else {
                continue;
            };
            let ret = body[..brace].split_once("->").map_or("", |(_, r)| r);
            let string = ret.trim() == "String";
            if !(ret.contains("PathBuf")
                || ret.contains("&Path")
                || ret.contains("Path>")
                || string)
            {
                continue;
            }
            let mut rest = body[brace..].to_string();
            for r in READERS {
                while let Some(at) = rest.find(r) {
                    let Some(open) = rest[at..].find('(').map(|o| at + o) else {
                        break;
                    };
                    let end = open + call_args(&rest, open).len();
                    rest.replace_range(at..end, "");
                }
            }
            // lot 353 (re-check 2 of #563): a `String` path built by
            // `format!` (`SelfImage::exec_path`: `/proc/self/fd/N`, which a
            // worker's exec walked)
            let builders: &[&str] = if string {
                &["format!("]
            } else {
                &["PathBuf::from(", "Path::new(", "PathBuf::from(format!("]
            };
            let built = builders.iter().any(|c| {
                ["\"/proc", "\"/sys"]
                    .iter()
                    .any(|v| rest.contains(&format!("{c}{v}")))
            });
            if built {
                if let Some((name, params)) = signature(body) {
                    let method = params.first().is_some_and(|p| p == "self");
                    out.push((f.clone(), if method { format!(".{name}") } else { name }));
                }
            }
        }
    }
    // lot 353 (re-check 2 of #563, R2-3): and to a fixpoint, the functions
    // returning a path that return what one of those returns — the
    // sampler's `host_view` returns `response::host_path(p)`
    loop {
        let before = out.len();
        for (f, text) in code {
            if f == KERNEL_ROOTS {
                continue;
            }
            for (_, body) in fn_bodies(text) {
                let Some(brace) = body.find('{') else {
                    continue;
                };
                let ret = body[..brace].split_once("->").map_or("", |(_, r)| r);
                if !(ret.contains("PathBuf") || ret.contains("&Path") || ret.contains("Path>")) {
                    continue;
                }
                let Some((name, _)) = signature(body) else {
                    continue;
                };
                if out.iter().any(|(of, n)| of == f && *n == name) {
                    continue;
                }
                let inner = &body[brace..];
                let calls = out.iter().any(|(rf, rn)| {
                    let call = if rf == f {
                        format!("{rn}(")
                    } else {
                        format!("{}::{rn}(", module_of(rf))
                    };
                    inner.match_indices(&call).any(|(at, _)| {
                        !inner[..at]
                            .chars()
                            .next_back()
                            .is_some_and(|c| c.is_alphanumeric() || c == '_')
                    })
                });
                if calls {
                    out.push((f.clone(), name));
                }
            }
        }
        if out.len() == before {
            break;
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Lot 353 (re-check 2 of #563, plant R): the fields `text`'s functions set
/// to a path under a view — a struct literal's `root: "/proc".into()`,
/// `root: proc_root.into()` with `proc_root` a parameter handed one, its
/// shorthand `Self { proc_root }` — each as `self.<field>`: a walk by path
/// of the field in any method of the file is a walk of the view (the
/// decision's `ProcFacts::trusted_exe` opened `self.root`'s
/// `/proc/<pid>/exe` by path; no name of [`VIEW_NAMES`] told it).
fn view_fields(
    text: &str,
    constants: &[String],
    params: &BTreeMap<usize, Vec<String>>,
) -> Vec<String> {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut out: Vec<String> = Vec::new();
    for (base, body) in fn_bodies(text) {
        let mut tainted = constants.to_vec();
        tainted.extend(params.get(&base).cloned().unwrap_or_default());
        tainted.extend(view_locals(body, &tainted));
        let b = body.as_bytes();
        for (at, _) in body.match_indices(':') {
            if b.get(at + 1) == Some(&b':') || (at > 0 && b[at - 1] == b':') {
                continue;
            }
            let head = body[..at].trim_end();
            let name: String = head
                .chars()
                .rev()
                .take_while(|c| ident(*c))
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            if name.is_empty() || name.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                continue;
            }
            let before = head[..head.len() - name.len()].trim_end();
            if !(before.ends_with('{') || before.ends_with(',')) {
                continue;
            }
            let rest = &body[at + 1..];
            let mut depth = 0i32;
            let mut end = rest.len();
            for (i, c) in rest.char_indices() {
                match c {
                    '(' | '[' | '{' => depth += 1,
                    ')' | ']' | '}' if depth == 0 => {
                        end = i;
                        break;
                    }
                    ')' | ']' | '}' => depth -= 1,
                    ',' | ';' if depth == 0 => {
                        end = i;
                        break;
                    }
                    _ => {}
                }
            }
            // what a call of anything but a path's builder makes of a view
            // path is no path (`open_dir(&host.join("objects"))?`: a
            // descriptor)
            let value = path_builders_only(&rest[..end]);
            if names_view_path(&value, &tainted) {
                out.push(format!("self.{name}"));
            }
        }
        // the shorthand: `Self { proc_root, … }` — of a local that is a
        // path (not what a call made of one: a descriptor)
        let mut paths = constants.to_vec();
        paths.extend(params.get(&base).cloned().unwrap_or_default());
        loop {
            let before = paths.len();
            for (at, _) in body.match_indices("let ") {
                let rest = &body[at + 4..];
                let rest = rest.strip_prefix("mut ").unwrap_or(rest);
                let name: String = rest.chars().take_while(|c| ident(*c)).collect();
                let Some(eq) = rest.find('=') else { continue };
                let expr = &rest[eq + 1..];
                let expr = &expr[..expr.find(';').unwrap_or(expr.len())];
                if !name.is_empty()
                    && !paths.contains(&name)
                    && names_view_path(&path_builders_only(expr), &paths)
                {
                    paths.push(name);
                }
            }
            if paths.len() == before {
                break;
            }
        }
        // `Self {` and any `Type {` (a struct literal: `CopyScan { host, … }`)
        let mut literals: Vec<usize> = Vec::new();
        for (at, _) in body.match_indices('{') {
            let head = body[..at].trim_end();
            let ty: String = head
                .chars()
                .rev()
                .take_while(|c| ident(*c))
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            if ty.chars().next().is_some_and(|c| c.is_uppercase()) {
                literals.push(at);
            }
        }
        for open in literals {
            let end = open + support::matching_brace(&body[open..]);
            let inner = &body[open + 1..end.saturating_sub(1).max(open + 1)];
            for item in top_level_split(inner) {
                let item = item.trim();
                if !item.contains(':') && paths.iter().any(|t| t == item) {
                    out.push(format!("self.{item}"));
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// `expr` with every call removed but those of a path's builders
/// (`.join`, `.into`, `PathBuf::from`, `format!`…): what is left names a
/// view only when the expression is one's path.
fn path_builders_only(expr: &str) -> String {
    const BUILDERS: &[&str] = &[
        ".join",
        ".into",
        ".to_path_buf",
        ".to_owned",
        ".clone",
        ".as_ref",
        ".as_path",
        ".to_string",
        "PathBuf::from",
        "PathBuf::new",
        "Path::new",
        "String::from",
        "format!",
        "host_path",
        "host_view",
    ];
    let mut out = expr.to_string();
    let mut from = 0;
    while let Some(open) = out[from..].find('(').map(|i| from + i) {
        let name = callee(&out, open);
        let start = open - name.len();
        if name.is_empty() || BUILDERS.iter().any(|b| name.ends_with(b)) {
            from = open + 1;
            continue;
        }
        let end = open + call_args(&out, open).len();
        out.replace_range(start..end, " ");
        from = start;
    }
    out
}

/// Lot 353 (re-check 2 of #563, R2-3): the functions, by name, that call a
/// callable parameter of theirs with a path under a view, each with that
/// parameter's index — `response::on_host_path(path, op)` calls
/// `op(&host_path(path))` — and to a fixpoint the functions that hand such
/// a callable on (`DecisionHost::on_host_path(path, op)` in its impl): the
/// parameters of the closure a caller hands there are paths under a view
/// (`accounts::read`'s `|p| File::open(p)` opened `/proc/1/root/etc/passwd`
/// by path on the decision thread).
fn view_handing_fns(
    code: &BTreeMap<String, String>,
    constants: &[String],
    returning: &[(String, String)],
) -> BTreeMap<String, Vec<usize>> {
    let mut out: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    loop {
        let mut grew = false;
        for (f, text) in code {
            let consts = constants_of(f, constants, returning);
            let params = view_params(text, &consts, &BTreeMap::new());
            for (base, body) in fn_bodies(text) {
                let Some((name, ps)) = signature(body) else {
                    continue;
                };
                let Some(brace) = body.find('{') else {
                    continue;
                };
                let inner = &body[brace..];
                let mut tainted = consts.clone();
                tainted.extend(params.get(&base).cloned().unwrap_or_default());
                tainted.extend(view_locals(body, &tainted));
                let skip = usize::from(ps.first().is_some_and(|p| p == "self"));
                for (i, p) in ps.iter().enumerate() {
                    if p == "self" || p.is_empty() {
                        continue;
                    }
                    let index = i - skip;
                    if out.get(&name).is_some_and(|v| v.contains(&index)) {
                        continue;
                    }
                    let pat = format!("{p}(");
                    let calls_with_view = inner.match_indices(&pat).any(|(at, _)| {
                        let before = inner[..at].chars().next_back();
                        if before.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '.') {
                            return false;
                        }
                        let open = at + p.len();
                        names_view_path(call_args(inner, open), &tainted)
                    });
                    // handed on, bare, to a function that hands it a view
                    let hands_on = out.iter().any(|(g, idx)| {
                        inner.match_indices(&format!("{g}(")).any(|(at, _)| {
                            let before = inner[..at].chars().next_back();
                            if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                                return false;
                            }
                            let open = at + g.len();
                            let args = call_args(inner, open);
                            let a = args.get(1..args.len().saturating_sub(1)).unwrap_or("");
                            let items = top_level_split(a);
                            idx.iter()
                                .any(|j| items.get(*j).is_some_and(|x| x.trim() == p.as_str()))
                        })
                    });
                    if calls_with_view || hands_on {
                        out.entry(name.clone()).or_default().push(index);
                        grew = true;
                    }
                }
            }
        }
        if !grew {
            return out;
        }
    }
}

/// The spans of the closures `body` hands to a function of `handing` at a
/// handing index, each with its parameters: within it they are paths
/// under a view.
fn handed_closures(
    body: &str,
    handing: &BTreeMap<String, Vec<usize>>,
) -> Vec<(std::ops::Range<usize>, Vec<String>)> {
    let mut out = Vec::new();
    for (g, idx) in handing {
        for (at, _) in body.match_indices(&format!("{g}(")) {
            let before = body[..at].chars().next_back();
            if before.is_some_and(|c| c.is_alphanumeric() || c == '_')
                || body[..at].ends_with("fn ")
            {
                continue;
            }
            let open = at + g.len();
            let args = call_args(body, open);
            let inner = args.get(1..args.len().saturating_sub(1)).unwrap_or("");
            let mut from = open + 1;
            for (j, item) in top_level_split(inner).into_iter().enumerate() {
                let start = from + (item.len() - item.trim_start().len());
                from += item.len() + 1;
                if !idx.contains(&j) {
                    continue;
                }
                let t = item.trim_start();
                let t = t.strip_prefix("move").map_or(t, str::trim_start);
                if !t.starts_with('|') {
                    continue;
                }
                let Some(close) = t[1..].find('|') else {
                    continue;
                };
                let params: Vec<String> = top_level_split(&t[1..1 + close])
                    .into_iter()
                    .map(|p| {
                        let p = p.split(':').next().unwrap_or("").trim();
                        p.trim_start_matches('&').trim().to_string()
                    })
                    .filter(|p| !p.is_empty() && p != "_")
                    .take(1)
                    .collect();
                if !params.is_empty() {
                    out.push((start..start + item.trim_start().len(), params));
                }
            }
        }
    }
    out
}

/// Lot 353 (re-check 1 of #563, N2 B): the walks that start at `/` by path
/// in one file's production code — an open of the literal `/` (`c"/"`,
/// `"/"`) as a directory to walk from: such a walk crosses whatever is
/// mounted on `/proc` or `/sys` now, `kernel_roots::walk_root` starts a
/// view's at its anchored root.
fn root_walks(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let line_of = |at: usize| text[..at].matches('\n').count();
    let mut out = std::collections::BTreeSet::new();
    for lit in ["c\"/\"", "\"/\"", "\"/\\0\"", "b\"/\\0\""] {
        for (at, _) in text.match_indices(lit) {
            // the literal itself, not the end of a longer one
            if text[..at].ends_with('\\') || text[..at].ends_with('"') {
                continue;
            }
            let mut i = at;
            while let Some(open) = enclosing_open(text, i) {
                let name = callee(text, open);
                let last = name.rsplit([':', '.']).next().unwrap_or(name);
                if last.contains("open") {
                    let n = line_of(at);
                    out.insert(format!(
                        "{}: {}",
                        n + 1,
                        lines.get(n).map_or("", |l| l.trim())
                    ));
                    break;
                }
                i = open;
            }
        }
    }
    out.into_iter().collect()
}

/// The parameter lists of the closures in `stmt` (`|p|`, `|(a, b)|`,
/// `move |x: &str|`), each parameter without its type.
fn closure_params(stmt: &str) -> Vec<String> {
    let b = stmt.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'|' || b.get(i + 1) == Some(&b'|') {
            i += if b[i] == b'|' { 2 } else { 1 };
            continue;
        }
        let before = stmt[..i].trim_end();
        let opens = before.ends_with('(') || before.ends_with(',') || before.ends_with("move");
        let Some(close) = stmt[i + 1..].find('|').map(|c| i + 1 + c) else {
            break;
        };
        if opens {
            for p in top_level_split(&stmt[i + 1..close]) {
                out.push(p.split(':').next().unwrap_or("").to_string());
            }
            i = close + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// The by-path calls ([`PATH_CALLS`]) and methods ([`PATH_METHODS`]) in
/// `body[span]` whose path names a view (`tainted`), each told at its offset.
fn path_uses(
    body: &str,
    span: std::ops::Range<usize>,
    tainted: &[String],
    flag: &mut dyn FnMut(usize),
) {
    let within = |at: usize| span.contains(&at);
    for call in PATH_CALLS {
        for (at, _) in body.match_indices(call).filter(|(at, _)| within(*at)) {
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
            // an `*at` call's directory is a descriptor, not a path: its
            // path arguments are the rest (re-check 1 of #563, N2 C)
            let args =
                if call.ends_with("at(") || call.ends_with("at64(") || *call == "libc::statx(" {
                    let inner = args.get(1..args.len().saturating_sub(1)).unwrap_or("");
                    top_level_split(inner)
                        .into_iter()
                        .skip(1)
                        .collect::<Vec<_>>()
                        .join(",")
                } else {
                    args.to_string()
                };
            if names_view_path(&args, tainted) {
                flag(at);
            }
        }
    }
    for method in PATH_METHODS {
        for (at, _) in body.match_indices(method).filter(|(at, _)| within(*at)) {
            let rcv = receiver(body, at);
            // an open file's own metadata asks no path (`fstat`)
            let last = rcv.rsplit(['.', ':', '&']).next().unwrap_or(rcv);
            if *method == ".metadata()" && FILE_HANDLES.contains(&last) {
                continue;
            }
            // a `Metadata` or a `FileType` asks nothing either
            if rcv.chars().all(|c| c.is_alphanumeric() || c == '_') && VALUE_NAMES.contains(&rcv) {
                continue;
            }
            if names_view_path(rcv, tainted) {
                flag(at);
            }
        }
    }
}

/// Rule 1's violations in one file's production code: `line: text`.
fn walks(text: &str, constants: &[String]) -> Vec<String> {
    walks_with(text, constants, &BTreeMap::new())
}

/// [`walks`], with the parameters other files' calls hand a view path
/// (`seed`, by function offset: [`cross_file_params`]).
fn walks_with(
    text: &str,
    constants: &[String],
    seed: &BTreeMap<usize, Vec<String>>,
) -> Vec<String> {
    walks_full(text, constants, seed, &BTreeMap::new())
}

/// [`walks_with`], with the functions that hand their callable parameter a
/// view path ([`view_handing_fns`]): the closures handed to them are
/// scanned with their parameter tainted. Lot 353 (re-check 2 of #563): and
/// the fields the file's functions set to a view path ([`view_fields`]).
fn walks_full(
    text: &str,
    constants: &[String],
    seed: &BTreeMap<usize, Vec<String>>,
    handing: &BTreeMap<String, Vec<usize>>,
) -> Vec<String> {
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
    let params = view_params(text, constants, seed);
    let fields = view_fields(text, constants, &params);
    for (base, body) in fn_bodies(text) {
        let mut tainted = constants.to_vec();
        tainted.extend(fields.iter().cloned());
        tainted.extend(params.get(&base).cloned().unwrap_or_default());
        tainted.extend(view_locals(body, &tainted));
        // lot 353 (re-check 2 of #563, R2-3): the closures handed to a
        // function that calls them with a view path
        for (span, ps) in handed_closures(body, handing) {
            let mut t = tainted.clone();
            t.extend(ps);
            let locals = view_locals(&body[span.clone()], &t);
            t.extend(locals);
            path_uses(body, span, &t, &mut |at| flag(base + at));
        }
        // lot 353 (re-check 1 of #563, N2 B, N3): any call whose directory
        // is `AT_FDCWD` — a closure or a helper around `openat` — opens its
        // path by path
        for (at, _) in body.match_indices("libc::AT_FDCWD") {
            if let Some(open) = enclosing_open(body, at) {
                if names_view_path(call_args(body, open), &tainted) {
                    flag(base + at);
                }
            }
        }
        path_uses(body, 0..body.len(), &tainted, &mut |at| flag(base + at));
        // lot 353 (re-check 1 of #563, N2 D): the items of a list of view
        // paths, within the loop or the statement that binds them
        for (span, t) in scope_taint(body, &tainted) {
            path_uses(body, span, &t, &mut |at| flag(base + at));
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
            (w[0].starts_with("#[cfg(test)]") || w[0].starts_with("#[cfg(any(test"))
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
    // the bpffs pin root it prepares (`/sys/fs/bpf/northnarrow`)
    "prepare_pin_root",
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
        "crates/nn-linux/src/fs_type.rs",
        1,
        "`magic_of_path`'s statfs by path is the branch of a path under no view (automounts \
         followed): a path under one is opened beneath its anchored root first \
         (`kernel_roots::view_of`, `open_crossing`) — the re-check of #563's cross-file rule \
         sees the tracefs roots handed to it",
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
        // re-check 2 of #563: 3 → 6, no new walk — the field rule sees the
        // probe instance's reads and removal (`self.instance`, a tracefs path)
        6,
        "the verifier gate (a lab build's --verifier-check, a process of its own, never the \
         agent's run): its kprobe instance created in tracefs, read and removed, its \
         `kprobe_events` appended",
    ),
    (
        "crates/nn-linux/src/sensor_feasibility.rs",
        1,
        "the sensor-feasibility gate (a lab build's --sensor-feasibility, a process of its own, \
         never the agent's run): its exec of a memfd through `/proc/<pid>/fd/N`, the very \
         launch it measures the exec sensor on (re-check 2 of #563: the exec rule sees it)",
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
    let returning = view_returning_fns(&code);
    assert!(
        constants.iter().any(|c| c == "MOUNTINFO_HOST"),
        "the scan finds the view constants: {constants:?}"
    );
    // re-check 1 of #563 (N2 D): a slice of view prefixes, over lines,
    // in another crate
    assert!(
        constants
            .iter()
            .any(|c| c == "MASS_WRITE_CARVEOUT_PREFIXES"),
        "the scan finds the slices of view paths: {constants:?}"
    );
    let cross = cross_file_params(&code, &constants);
    let handing = view_handing_fns(&code, &constants, &returning);
    assert!(
        handing.get("on_host_path").is_some_and(|i| i.contains(&1)),
        "the scan finds the functions handing a view path to a callable: {handing:?}"
    );
    let mut found = Vec::new();
    for (f, text) in code.iter().filter(|(f, _)| f.as_str() != KERNEL_ROOTS) {
        let w = walks_full(
            text,
            &constants_of(f, &constants, &returning),
            &cross.get(f).cloned().unwrap_or_default(),
            &handing,
        );
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

/// Lot 353 (re-check 1 of #563, N2 B): the opens of `/` that stay, by
/// file, and why — none walks from it.
const ROOT_OPENS: &[(&str, usize, &str)] = &[(
    "crates/nn-linux/src/sandbox/mod.rs",
    1,
    "the Landlock measurement opens `/` to see whether the domain refuses it, and closes it: \
     nothing is opened below it",
)];

/// Lot 353 (re-check 1 of #563, N1, N2 B): no walk starts at `/` by path
/// outside `kernel_roots` (`walk_root`): the open sensor's rule refresh
/// opened `/`, then `proc` below it, and the `fstat` of the FUSE mounted
/// over `/proc` held it.
#[test]
fn no_walk_starts_at_the_root_by_path() {
    let code = scan_code(&repo_root());
    let mut found = Vec::new();
    for (f, text) in code.iter().filter(|(f, _)| f.as_str() != KERNEL_ROOTS) {
        let w = root_walks(text);
        match ROOT_OPENS.iter().find(|(k, _, _)| k == f) {
            Some((_, n, _)) if w.len() == *n => {}
            Some((_, n, _)) => found.push(format!(
                "{f}: {} opens of `/`, {n} known (lower the pin when one goes): {w:?}",
                w.len()
            )),
            None => found.extend(w.into_iter().map(|l| format!("{f}:{l}"))),
        }
    }
    assert!(
        found.is_empty(),
        "a walk from `/` by path crosses the /proc or /sys mounted now: start it with \
         antitamper_bpf::kernel_roots::walk_root (a view's walk starts at its anchored root):\n{}",
        found.join("\n")
    );
}

/// Lot 353 (re-check 1 of #563, N2): each of the four shapes the
/// re-check planted, and the two walks it found (N1's carve-out walk, N3's
/// canary root), fail the rules.
#[test]
fn the_re_check_s_planted_shapes_are_found() {
    // B: a component walk from `/` through a closure (N1's shape)
    let b = "pub fn rev563_walk() -> i32 {\n    let open = |at: libc::c_int, n: &std::ffi::CStr| \
             unsafe { libc::openat(at, n.as_ptr(), libc::O_PATH) };\n    let root = \
             open(libc::AT_FDCWD, c\"/\");\n    open(root, c\"proc\")\n}\n";
    assert!(!root_walks(b).is_empty(), "B: {b}");
    let n1 = "fn place_carveout(path: &Path) -> std::io::Result<CarveoutPlace> {\n    let open = \
              |at: libc::c_int, name: &std::ffi::CStr| -> std::io::Result<std::fs::File> {\n        \
              let fd = unsafe {\n            libc::openat(\n                at,\n                \
              name.as_ptr(),\n                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,\n            \
              )\n        };\n        todo!()\n    };\n    let mut cur = open(libc::AT_FDCWD, \
              c\"/\")?;\n    todo!()\n}\n";
    assert!(!root_walks(n1).is_empty(), "N1: {n1}");
    for clean in [
        "fn f() {\n    let (start, names) = kernel_roots::walk_root(Path::new(\"/\"))?;\n}\n",
        "fn f() {\n    let ok = path.starts_with(\"/\");\n    let r = libc::mount(std::ptr::null(), \
         c\"/\".as_ptr(), std::ptr::null(), 0, std::ptr::null());\n}\n",
        "fn f() {\n    let x = Path::new(\"/proc/\");\n    let y = \"a/\";\n}\n",
    ] {
        assert!(root_walks(clean).is_empty(), "{clean}");
    }
    // C: fstatat (and any `*at` call) with a view path, whatever the dirfd
    let c = "pub fn rev563_fstatat() -> i32 {\n    let mut st: libc::stat = unsafe { \
             std::mem::zeroed() };\n    unsafe { libc::fstatat(libc::AT_FDCWD, \
             c\"/proc/1\".as_ptr(), &mut st, 0) }\n}\n";
    assert!(!walks(c, &[]).is_empty(), "C: {c}");
    let c2 = "fn f(dir: &File) {\n    unsafe { libc::statx(dir.as_raw_fd(), c\"/sys/x\".as_ptr(), \
              0, 0, &mut sx) };\n}\n";
    assert!(!walks(c2, &[]).is_empty(), "C (statx): {c2}");
    // D: a slice constant of view prefixes, over several lines, walked
    let d_code = BTreeMap::from([(
        "x.rs".to_string(),
        "pub const REV563_PREFIXES: &[&str] = &[\n    \"/proc/\",\n];\npub fn rev563_prefixes() \
         -> usize {\n    REV563_PREFIXES.iter().filter(|p| \
         std::path::Path::new(p).exists()).count()\n}\n"
            .to_string(),
    )]);
    let d_consts = view_constants(&d_code);
    assert_eq!(d_consts, vec!["REV563_PREFIXES".to_string()]);
    assert!(
        !walks(&d_code["x.rs"], &d_consts).is_empty(),
        "D (a closure)"
    );
    let d2 =
        "fn g() {\n    for p in REV563_PREFIXES {\n        let _ = std::fs::metadata(p);\n    \
              }\n}\n";
    assert!(!walks(d2, &d_consts).is_empty(), "D (a for loop)");
    // the items of a list that names no view are not
    let d3 = "fn g() {\n    for p in OTHER {\n        let _ = std::fs::metadata(p);\n    }\n    \
              let n = OTHER.iter().filter(|p| Path::new(p).exists()).count();\n}\n";
    assert!(walks(d3, &d_consts).is_empty(), "{d3}");
    // A: a helper in another file handed a view path
    let a_code = BTreeMap::from([
        (
            "crates/nn-linux/src/host_hardening.rs".to_string(),
            "pub fn rev563_stat_it(p: &std::path::Path) -> bool {\n    \
             std::fs::metadata(p).is_ok()\n}\n"
                .to_string(),
        ),
        (
            "crates/nn-linux/src/own_dropins.rs".to_string(),
            "pub fn rev563_call() -> bool {\n    \
             crate::host_hardening::rev563_stat_it(std::path::Path::new(\"/proc/1/status\"))\n}\n"
                .to_string(),
        ),
    ]);
    let cross = cross_file_params(&a_code, &[]);
    let hh = "crates/nn-linux/src/host_hardening.rs";
    assert!(
        walks(&a_code[hh], &[]).is_empty(),
        "alone, the helper is clean"
    );
    assert!(
        !walks_with(
            &a_code[hh],
            &[],
            &cross.get(hh).cloned().unwrap_or_default()
        )
        .is_empty(),
        "A: {cross:?}"
    );
    // N3: the canary's root, a function returning `/proc/1/root`, opened
    // by path through a helper around `openat`
    let n3_code = BTreeMap::from([(
        "x.rs".to_string(),
        "fn write_checked() {\n    write_beneath(&host_root(), &canonical);\n}\nfn host_root() -> \
         PathBuf {\n    if antitamper_bpf::kernel_roots::metadata(\"/proc/1/root/\").is_ok() {\n        \
         PathBuf::from(\"/proc/1/root\")\n    } else {\n        PathBuf::from(\"/\")\n    }\n}\nfn \
         write_beneath(root: &Path, dir: &Path) {\n    let open_dir = |at: libc::c_int, name: \
         &CString| unsafe { libc::openat(at, name.as_ptr(), 0) };\n    let mut cur = \
         open_dir(libc::AT_FDCWD, &cstr(root.as_os_str())?, 0)?;\n}\n"
            .to_string(),
    )]);
    let n3_consts = constants_of("x.rs", &[], &view_returning_fns(&n3_code));
    assert_eq!(n3_consts, vec!["host_root".to_string()]);
    assert_eq!(
        constants_of("y.rs", &[], &view_returning_fns(&n3_code)),
        vec!["x::host_root".to_string()],
        "elsewhere by its module path"
    );
    assert!(
        !walks(&n3_code["x.rs"], &n3_consts).is_empty(),
        "N3: the root opened by path"
    );
    // a function that reads a view through a reader and returns another
    // path is not one
    let not = BTreeMap::from([(
        "x.rs".to_string(),
        "fn f() -> PathBuf {\n    let t = kernel_roots::read_text(\"/proc/self/cgroup\");\n    \
         PathBuf::from(\"/etc\")\n}\n"
            .to_string(),
    )]);
    assert!(view_returning_fns(&not).is_empty());
}

/// Lot 353 (re-check 2 of #563): the shapes the second re-check planted
/// (its probe `rev563-probe-r2-ratchet`) and the three walks it found, each
/// failing rule 1 — plant R (a field named `root` holding `/proc`, the
/// decision's `ProcFacts::trusted_exe`), plant M (an exec of
/// `/proc/self/exe`, the start's self-test; `/proc/self/fd/N`, a worker's
/// launch), plant E (a helper imported and called bare), the closure a
/// function calls with the host's view (`on_host_path`'s op: the account
/// database read on the decision thread), a callable returning the host's
/// view handed by name (the entropy sampler's `&host_view`), and a
/// function returning what a view-returning one returns.
#[test]
fn the_re_check_2_s_planted_shapes_are_found() {
    // R: a field not named as a view
    let r = "pub struct Rev563Facts { root: std::path::PathBuf }\nimpl Rev563Facts {\n    pub fn \
             new() -> Self { Self { root: \"/proc\".into() } }\n    pub fn exe_open(&self, pid: \
             u32) -> bool {\n        let link = self.root.join(pid.to_string()).join(\"exe\");\n        \
             std::fs::File::open(&link).is_ok()\n    }\n}\n";
    assert!(!walks(r, &[]).is_empty(), "R: {r}");
    // R through a constructor's parameter (the decision host's own shape)
    let r2 = "impl ProcFacts {\n    pub fn new(at: impl Into<PathBuf>) -> Self {\n        Self { \
              root: at.into(), hashes: Mutex::default() }\n    }\n    fn trusted_exe(&self, pid: \
              u32) {\n        let link = self.root.join(pid.to_string()).join(\"exe\");\n        \
              let f = std::fs::File::open(&link);\n    }\n}\nimpl Default for ProcFacts {\n    \
              fn default() -> Self {\n        Self::new(\"/proc\")\n    }\n}\n";
    assert!(
        !walks(r2, &[]).is_empty(),
        "R (a constructor's parameter): {r2}"
    );
    // a field set to what a call made of a view path is a descriptor
    let fd_field = "impl J {\n    fn open(path: &Path) -> Self {\n        let host = \
                    PathBuf::from(\"/proc/1/root\").join(path);\n        let evidence = \
                    open_dir(&host.join(\"evidence\")).unwrap();\n        Self { evidence }\n    \
                    }\n    fn mv(&self) {\n        unsafe { libc::renameat(0, a.as_ptr(), \
                    self.evidence.as_raw_fd(), b.as_ptr()) };\n    }\n}\n";
    assert!(walks(fd_field, &[]).is_empty(), "{fd_field}");
    // M: an exec of a view path, a literal or a local
    for m in [
        "fn f() {\n    let ok = std::process::Command::new(\"/proc/self/exe\").arg(\"x\").status();\n}\n",
        "fn f() {\n    let exe = Path::new(\"/proc/self/exe\");\n    let mut cmd = Command::new(exe);\n}\n",
        "fn f(fd: i32) {\n    let mut cmd = Command::new(format!(\"/proc/self/fd/{fd}\"));\n}\n",
        "fn f() {\n    unsafe { libc::execv(c\"/proc/self/fd/3\".as_ptr(), argv.as_ptr()) };\n}\n",
    ] {
        assert!(!walks(m, &[]).is_empty(), "M: {m}");
    }
    // M through a method returning a view path (`SelfImage::exec_path`)
    let m_code = BTreeMap::from([
        (
            "crates/nn-linux/src/worker/mod.rs".to_string(),
            "impl SelfImage {\n    pub fn exec_path(&self) -> String {\n        \
             format!(\"/proc/self/fd/{}\", self.fd.as_raw_fd())\n    }\n}\n"
                .to_string(),
        ),
        (
            "crates/nn-linux/src/worker/spawn.rs".to_string(),
            "pub fn spawn(image: &SelfImage) {\n    let mut cmd = \
             Command::new(image.exec_path());\n}\n"
                .to_string(),
        ),
    ]);
    let returning = view_returning_fns(&m_code);
    let sp = "crates/nn-linux/src/worker/spawn.rs";
    assert!(
        !walks(&m_code[sp], &constants_of(sp, &[], &returning)).is_empty(),
        "M (a method): {returning:?}"
    );
    // E: a helper imported and called bare, from another file
    let e_code = BTreeMap::from([
        (
            "crates/nn-linux/src/host_hardening.rs".to_string(),
            "pub fn rev563_stat_it(p: &std::path::Path) -> bool {\n    \
             std::fs::metadata(p).is_ok()\n}\n"
                .to_string(),
        ),
        (
            "crates/nn-linux/src/own_dropins.rs".to_string(),
            "use crate::host_hardening::rev563_stat_it;\npub fn rev563_call_bare() -> bool {\n    \
             rev563_stat_it(std::path::Path::new(\"/proc/1/status\"))\n}\n"
                .to_string(),
        ),
    ]);
    let cross = cross_file_params(&e_code, &[]);
    let hh = "crates/nn-linux/src/host_hardening.rs";
    assert!(
        !walks_with(
            &e_code[hh],
            &[],
            &cross.get(hh).cloned().unwrap_or_default()
        )
        .is_empty(),
        "E: {cross:?}"
    );
    // the closure a function calls with the host's view, in another file
    // (the account database, on the decision thread) — and handed on by a
    // trait's impl (nn-core's `H::on_host_path`)
    let h_code = BTreeMap::from([
        (
            "crates/nn-linux/src/response/mod.rs".to_string(),
            "pub fn host_path(path: &Path) -> PathBuf {\n    \
             Path::new(\"/proc/1/root\").join(path)\n}\npub fn on_host_path<T>(path: &Path, op: \
             impl Fn(&Path) -> io::Result<T>) -> io::Result<T> {\n    op(&host_path(path))\n}\n"
                .to_string(),
        ),
        (
            "crates/nn-linux/src/decision_host_linux.rs".to_string(),
            "impl DecisionHost for LinuxHost {\n    fn on_host_path<T>(path: &Path, op: impl \
             Fn(&Path) -> io::Result<T>) -> io::Result<T> {\n        \
             crate::response::on_host_path(path, op)\n    }\n}\n"
                .to_string(),
        ),
        (
            "crates/nn-linux/src/accounts.rs".to_string(),
            "fn read(path: &str) -> String {\n    crate::response::on_host_path(Path::new(path), \
             |p| {\n        let mut s = Vec::new();\n        \
             std::fs::File::open(p)?.read_to_end(&mut s)?;\n        Ok(s)\n    })\n}\n"
                .to_string(),
        ),
        (
            "crates/nn-core/src/impact/mod.rs".to_string(),
            "fn copy_beside<H: DecisionHost>(d: &str) -> bool {\n    \
             H::on_host_path(Path::new(d), |p| std::fs::symlink_metadata(p)).is_ok()\n}\n"
                .to_string(),
        ),
    ]);
    let returning = view_returning_fns(&h_code);
    let handing = view_handing_fns(&h_code, &[], &returning);
    assert_eq!(handing.get("on_host_path"), Some(&vec![1]), "{handing:?}");
    for f in [
        "crates/nn-linux/src/accounts.rs",
        "crates/nn-core/src/impact/mod.rs",
    ] {
        assert!(
            !walks_full(
                &h_code[f],
                &constants_of(f, &[], &returning),
                &BTreeMap::new(),
                &handing
            )
            .is_empty(),
            "the handed closure: {f}"
        );
    }
    // the same closure reading through kernel_roots is clean
    let clean =
        "fn read(path: &str) -> String {\n    crate::response::on_host_path(Path::new(path), \
                 |p| {\n        antitamper_bpf::kernel_roots::open(p, libc::O_RDONLY)\n    })\n}\n";
    assert!(
        walks_full(clean, &[], &BTreeMap::new(), &handing).is_empty(),
        "{clean}"
    );
    // a callable returning the host's view, handed by name (the sampler),
    // through a function that returns another one's view path
    let s_code = BTreeMap::from([
        (
            "crates/nn-linux/src/response/mod.rs".to_string(),
            "pub fn host_path(path: &Path) -> PathBuf {\n    \
             Path::new(\"/proc/1/root\").join(path)\n}\n"
                .to_string(),
        ),
        (
            "crates/nn-linux/src/impact/entropy.rs".to_string(),
            "fn host_view(p: &Path) -> PathBuf {\n    crate::response::host_path(p)\n}\nfn \
             sample(path: &str) -> u8 {\n    sample_dir(Path::new(path), &host_view)\n}\npub fn \
             sample_dir(path: &Path, host: &dyn Fn(&Path) -> PathBuf) -> u8 {\n    let entries = \
             std::fs::read_dir(host(path));\n    0\n}\n"
                .to_string(),
        ),
    ]);
    let returning = view_returning_fns(&s_code);
    assert!(
        returning.iter().any(|(_, n)| n == "host_view"),
        "transitive: {returning:?}"
    );
    let en = "crates/nn-linux/src/impact/entropy.rs";
    assert!(
        !walks(&s_code[en], &constants_of(en, &[], &returning)).is_empty(),
        "the sampler's callable"
    );
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
    // lot 353 (re-check 1 of #563): the other periodic tasks of the
    // runtime that walk a path by path (the pins under `/sys/fs/bpf`,
    // `/run/northnarrow`, the system's bin directories): each tick's walk
    // off the worker — a mount there that does not answer holds a thread,
    // never a worker the status answers on
    (
        "crates/nn-linux/src/anti_tamper/bpf_defense.rs",
        "\"BPF self-defence: link self-check armed\"",
        &["off_the_runtime(|| live_links(own.pin_root.as_deref()))"],
    ),
    (
        "crates/nn-linux/src/telemetry_probe.rs",
        "async fn run_round(",
        &[
            "off_the_runtime(|| {",
            "kernel_roots::write(&file,",
            "off_the_runtime(|| AttachView::read(env))",
        ],
    ),
    (
        "crates/nn-linux/src/telemetry_probe.rs",
        "off_the_runtime(|| AttachView::read(env))",
        &["off_the_runtime(|| prepare_deny("],
    ),
    (
        "agent/src/boot/tasks.rs",
        "let installer_ticker = installer_override.clone();",
        &["off_the_runtime(|| {", "installer_ticker.close_if_expired("],
    ),
    (
        "agent/src/boot/tasks.rs",
        "pub(crate) fn spawn_shutdown_exe_refresh()",
        &["off_the_runtime(|| {", "refresh_shutdown_exe(root)"],
    ),
    (
        "agent/src/boot/tasks.rs",
        "pub(crate) fn spawn_program_images_refresh()",
        &["off_the_runtime(nn_linux::program_images::refresh)"],
    ),
    (
        "agent/src/boot/tasks.rs",
        "let mut tick_once = || {",
        &["resolve_verified_watchdog_pid(&pidfile, &expected_exe)"],
    ),
    (
        "agent/src/boot/tasks.rs",
        "nn_linux::runtime::off_the_runtime(&mut tick_once);",
        &["off_the_runtime(&mut tick_once)"],
    ),
    // lot 353 (re-check 2 of #563, R2-1): the whole check — the look and
    // the rebind — on its own helper thread; the serve loop starts it and
    // takes its answer, the start's bind bounded
    (
        "agent/src/admin/socket_watch.rs",
        "pub fn start_check(&mut self)",
        &[
            "std::thread::Builder::new()",
            "let looked = look_and_rebind(&path, bound);",
        ],
    ),
    (
        "agent/src/admin/socket_watch.rs",
        "pub fn look_and_rebind(",
        &["path_state(path, bound)", "bind_std(path)"],
    ),
    (
        "agent/src/admin/socket_watch.rs",
        "pub async fn bind_within(",
        &[
            "std::thread::Builder::new()",
            "tokio::time::timeout(deadline, rx)",
        ],
    ),
    (
        "agent/src/admin/transport.rs",
        "let mut looking: Option<",
        &[
            "looking = watch.start_check();",
            "watch.finish(looked, audit_log.as_ref())",
        ],
    ),
    (
        "agent/src/admin/transport.rs",
        "socket_watch::bind_within(",
        &["socket_watch::BIND_DEADLINE).await?"],
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

/// Lot 353 (re-check 1 of #563, N1): the open sensor's rules are built
/// from the host only through `build_bounded` (a helper thread with a
/// deadline), at the start and in the refresher — which runs on a thread of
/// its own (`PumpThread::every`), never a task of the runtime: a FUSE over
/// `/proc` held its build on a runtime worker every minute.
#[test]
fn the_open_sensor_rules_are_built_off_the_runtime() {
    let code = scan_code(&repo_root());
    let build = "RuleSet::build(&RuleInputs::from_host(";
    let users: Vec<&String> = code
        .iter()
        .filter(|(_, t)| t.contains(build))
        .map(|(f, _)| f)
        .collect();
    assert_eq!(
        users,
        vec!["crates/nn-linux/src/sensors/open_sensor.rs"],
        "the host's rules are built in the open sensor only"
    );
    let os = &code["crates/nn-linux/src/sensors/open_sensor.rs"];
    assert_eq!(os.matches(build).count(), 1, "once: in build_bounded");
    let b = body(os, "open_sensor.rs", "pub fn build_bounded(");
    assert!(
        b.contains(build) && b.contains("reader.run("),
        "built on the reader's helper thread:\n{b}"
    );
    let fim = &code["agent/src/boot/fim.rs"];
    let at = fim
        .find("let refresher = northnarrow_agent::sensors::pump::PumpThread::every(")
        .expect("the refresher is a thread of its own");
    let window: String = fim[at..].lines().take(40).collect::<Vec<_>>().join("\n");
    assert!(
        window.contains("refresh_rules.next(&BUILD_READER)"),
        "its build bounded:\n{window}"
    );
    assert!(
        window.contains("register_pump_thread(\"open_sensor_rules\""),
        "registered as a thread (a finished one stops the agent)"
    );
    assert!(
        !fim.contains("register_pump_handle(\"open_sensor_rules\""),
        "never a task of the runtime"
    );
    assert!(
        fim.contains("build_bounded(&BUILD_READER, extras)"),
        "the start's build bounded too"
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
