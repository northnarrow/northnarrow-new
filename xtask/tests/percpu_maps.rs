//! Lot 322 — what a per-CPU map may hold, and where the exec guards keep
//! their buffers.
//!
//! The exec environment's check (`EXECPOL_ENV`) refused 0 of 11 staging
//! preloads on Ubuntu 26.04's 7.0: its programs sat on the
//! `sys_enter_execve{,at}` tracepoints, and there a program attached as aya
//! and libbpf attach it (one perf event, CPU 0) ran only for the calls made
//! on CPU 0. The lab measured it with the kernel alone (`bpftrace`: the
//! tracepoint fired on CPU 0 only, pinned to CPU 1, 2 or 3 never; the
//! `sched_process_exec` tracepoint and the LSM hook on every CPU). The
//! environment is now read by the exec sensor's own LSM program, from the
//! exec's registers, into the task's own entry.
//!
//! The audit that came with it: an LSM, fentry/fexit or iterator program
//! runs with migration disabled but preemption enabled, so on a `full` or
//! `lazy` preemption kernel (Ubuntu 26.04's default) a per-CPU buffer kept
//! across a helper call can be rewritten by another task's run on the same
//! CPU. Every per-CPU map of `agent-ebpf` is listed here with why it is
//! safe, or why it is left for a follow-up; a new one fails until it is
//! classified. The exec guards' buffers (the exec sensor's walk, the
//! mapping check's walk, the environment, the quarantine's candidate, the
//! BPF guard's `OBJ_GET` path) are the running task's own entries.
//!
//! Lot 1.7b (stage S1, item F12): the object is read as Rust
//! (`support::ast`). A per-CPU map is a `static` whose type holds a per-CPU
//! map type anywhere — through an import's other name, parentheses, a
//! turbofish, an array, a generic's argument — and a `type` alias or a
//! struct's field that holds one is forbidden; the lexical scan (kept in
//! [`lexical`] only to show it) missed each spelling planted in
//! `the_lexical_bypasses_are_caught`. A map safe because of who runs it
//! (`PreemptOff`, `SingleReader`) is reached only by programs of that kind
//! (the review of #546: "a classification is not tied to a program type"),
//! through every function its programs may run ([`ast::Graph`]); a shared
//! helper whose argument keeps a program off the map is listed by name
//! ([`REACH_KNOWN`]). A function's body and a task entry's declaration are
//! found as Rust: one of each name, its `HashMap` aya's plain hash through
//! the imports.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use support::ast::{self, Corpus};
use support::{repo_root, strip_comments};
use syn::visit::{self, Visit};

fn code(rel: &str) -> String {
    strip_comments(
        &fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}")),
    )
}

/// `needles` all in `hay`, in this order.
fn in_order(hay: &str, needles: &[&str]) -> Result<(), String> {
    let mut at = 0;
    for n in needles {
        match hay[at..].find(n) {
            Some(i) => at += i + n.len(),
            None => return Err(format!("{n:?} not found after byte {at}")),
        }
    }
    Ok(())
}

/// The body of `fn name` in `code` (comments stripped), found as Rust (lot
/// 1.7b): the one function of that name — two fail, so a stale copy cannot
/// stand for the one the kernel runs — its text from its `{` to its `}`.
fn body<'a>(code: &'a str, name: &str) -> &'a str {
    let one: BTreeMap<String, String> = [("body.rs".to_string(), code.to_string())].into();
    let parsed = ast::parse_all(&one, false);
    let c = Corpus::of(&one, &parsed);
    let bodies: Vec<(usize, usize)> = c.files["body.rs"]
        .fns
        .iter()
        .filter(|f| f.name == name)
        .filter_map(|f| f.body)
        .map(|b| {
            (
                b.brace_token.span.open().byte_range().start,
                b.brace_token.span.close().byte_range().end,
            )
        })
        .collect();
    assert_eq!(bodies.len(), 1, "fn {name}: {} found", bodies.len());
    &code[bodies[0].0..bodies[0].1]
}

/// The `static NAME` of `rel` (comments stripped), found as Rust: `(its
/// type, its initialiser)`, whitespace dropped, and the full paths its
/// type's head may stand for through the file's imports (a `HashMap` that
/// is an LRU map under another name is not one).
fn static_decl(rel: &str, name: &str) -> (String, String, Vec<Vec<String>>) {
    static_decl_in(rel, &code(rel), name)
}

/// [`static_decl`] of `text`, read as the file `rel`.
fn static_decl_in(rel: &str, text: &str, name: &str) -> (String, String, Vec<Vec<String>>) {
    let one: BTreeMap<String, String> = [(rel.to_string(), text.to_string())].into();
    let parsed = ast::parse_all(&one, false);
    let c = Corpus::of(&one, &parsed);
    let mut found = Vec::new();
    struct V<'s>(&'s str, Vec<(String, String, Vec<String>)>);
    impl<'a> Visit<'a> for V<'_> {
        fn visit_item_static(&mut self, s: &'a syn::ItemStatic) {
            if s.ident == self.0 {
                let head = match &*s.ty {
                    syn::Type::Path(p) => ast::segments(&p.path),
                    _ => Vec::new(),
                };
                self.1
                    .push((ast::compact(&s.ty), ast::compact(&s.expr), head));
            }
        }
    }
    let mut v = V(name, Vec::new());
    v.visit_file(&parsed[rel]);
    found.extend(v.1);
    assert_eq!(
        found.len(),
        1,
        "{rel}: static {name}: {} found",
        found.len()
    );
    let (ty, init, head) = found.remove(0);
    let full = c.files[rel].full_paths(&head);
    (ty, init, full)
}

/// That `static NAME` of `rel` is `ty = init` as written (whitespace
/// dropped), its head aya's plain `HashMap`.
fn assert_task_map(rel: &str, name: &str, ty: &str, init: &str) {
    let (t, i, full) = static_decl(rel, name);
    let squeeze = |s: &str| s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    assert_eq!(t, squeeze(ty), "{rel}: static {name}'s type");
    assert_eq!(i, squeeze(init), "{rel}: static {name}'s initialiser");
    assert!(
        is_plain_hash(&full),
        "{rel}: static {name}'s HashMap is not aya's plain hash: {full:?}"
    );
}

/// Whether every import a type's head stands for is aya's plain
/// `HashMap` (and one does).
fn is_plain_hash(full: &[Vec<String>]) -> bool {
    let resolved: Vec<&Vec<String>> = full.iter().filter(|p| p.len() >= 2).collect();
    !resolved.is_empty()
        && resolved.iter().all(|p| {
            p[p.len() - 1] == "HashMap"
                && (p[..p.len() - 1] == ["aya_ebpf", "maps"]
                    || p[..p.len() - 1] == ["aya_ebpf", "maps", "hash_map"])
        })
}

/// Lot 1.7b: a task entry whose `HashMap` is an LRU map under that name (an
/// import's alias) is no plain hash; a tracepoint program whose attribute
/// takes arguments is counted; the census's iterator is a program of its
/// kind (`link_section = "iter/…"`).
#[test]
fn a_task_entry_under_another_map_s_name_is_caught() {
    let rel = "agent-ebpf/src/exec_lsm.rs";
    let text = code(rel);
    assert!(is_plain_hash(&static_decl_in(rel, &text, "EXEC_SCRATCH").2));
    let lru = format!("use aya_ebpf::maps::LruHashMap as HashMap;\n{text}");
    assert!(!is_plain_hash(&static_decl_in(rel, &lru, "EXEC_SCRATCH").2));
    // a second tracepoint program, its attribute with arguments, and a raw
    // one: the lexical count (`#[tracepoint]`) stays 1, the programs read
    // as Rust are three
    let pol = code("agent-ebpf/src/execpol.rs");
    let planted = format!(
        "{pol}\n#[tracepoint(category = \"syscalls\", name = \"sys_enter_execve\")]\n\
         pub fn planted_tp(ctx: TracePointContext) -> u32 {{\n    0\n}}\n\
         \n#[raw_tracepoint(tracepoint = \"sys_enter\")]\n\
         pub fn planted_raw(ctx: RawTracePointContext) -> i32 {{\n    0\n}}\n"
    );
    assert_eq!(planted.matches("#[tracepoint]").count(), 1);
    let tps = |t: &str| {
        programs_in("agent-ebpf/src/execpol.rs", t)
            .into_iter()
            .filter(|(_, k)| k.contains("tracepoint"))
            .count()
    };
    assert_eq!((tps(&pol), tps(&planted)), (1, 3));
    let census = programs_of("agent-ebpf/src/bpf_census.rs");
    assert!(
        census.contains(&("census_progs".to_string(), "iter".to_string())),
        "{census:?}"
    );
}

/// Why a per-CPU map is safe where it is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Why {
    /// Increments only, summed by the agent: an increment lost to an
    /// interleaved run costs one count, never a decision.
    Counter,
    /// A rate budget's window or an aggregate: an interleaved update lets
    /// one more record through or holds one back (each counted).
    RateState,
    /// One run of a program the kernel runs with preemption off (a classic
    /// or BTF tracepoint that is not a syscall's, a kprobe).
    PreemptOff,
    /// Written and read only by the agent's own read of an iterator, or by
    /// a diagnostic mode: no other run on the CPU.
    SingleReader,
}

/// Every per-CPU map of `agent-ebpf`, with why it is safe. The review of
/// #546 (F3): the FIM sensor's four buffers left here as a follow-up fed
/// posture-floor kills (FIM-010..017) and are per-task entries now.
const KNOWN: &[(&str, Why)] = &[
    ("RING_DROPS", Why::Counter),
    // lot 2.2: the window ring's drops, and its per-CPU sequence (an
    // increment an interleaved run loses repeats a number; the drop is
    // still counted)
    ("WINDOW_EVENT_DROPS", Why::Counter),
    ("WINDOW_EVENT_SEQ", Why::Counter),
    // lot 2.3a: the environment's read at `sched_process_exec` (a BTF
    // tracepoint), its length alone used
    ("TREE_ENV_SCRATCH", Why::PreemptOff),
    ("DENY_FAIL_OPEN", Why::Counter),
    ("EPG_COUNTERS", Why::Counter),
    ("EXECPOL_COUNTERS", Why::Counter),
    ("EXECQ_COUNTERS", Why::Counter),
    ("FLOW_SOCK_COUNTS", Why::Counter),
    ("OPEN_DEPTH_CAPPED", Why::Counter),
    ("TASK_DENIAL_RATE", Why::RateState),
    ("ATTEMPT_DENIAL_RATE", Why::RateState),
    // lot 318's re-check of #545: the non-decisive refusals' budget
    ("MINOR_DENIAL_RATE", Why::RateState),
    // kprobe `udp_sendmsg` / `udpv6_sendmsg`
    ("UDP_FLOWS", Why::RateState),
    // classic tracepoint `sched:sched_process_exec`
    ("STDIO_SCRATCH", Why::PreemptOff),
    // the review of #547 (F2, F5): the post-commit check's entry, classic
    // tracepoint `sched:sched_process_exec` (`execpol_env_commit`) only
    ("COMMIT_ENV", Why::PreemptOff),
    // the review of #547 (F6): the FIM sensor's opens without the task's
    // buffer
    ("OPEN_TASK_COUNTERS", Why::Counter),
    // `tp_btf/cgroup_attach_task`
    ("CGROUP_JOIN_PATH", Why::PreemptOff),
    // `iter/bpf_prog`, read by the agent's census only
    ("PROG_RECORD_SCRATCH", Why::SingleReader),
    // `--sensor-feasibility`'s probe program only
    ("PROBE_SCRATCH", Why::SingleReader),
];

/// The per-CPU map types of aya-ebpf.
const PER_CPU_TYPES: [&str; 3] = ["PerCpuArray", "PerCpuHashMap", "LruPerCpuHashMap"];

/// The program kinds that run with preemption off ([`Why::PreemptOff`]): a
/// classic or BTF tracepoint, a kprobe. (Which tracepoint a classic
/// program attaches to is the agent's choice: the exec policy's are
/// checked below, none on a syscall.)
const PREEMPT_OFF: [&str; 4] = ["tracepoint", "btf_tracepoint", "kprobe", "kretprobe"];

/// The program kinds of the object: an aya attribute, or an iterator's
/// `link_section`.
const KINDS: [&str; 12] = [
    "lsm",
    "fentry",
    "fexit",
    "kprobe",
    "kretprobe",
    "tracepoint",
    "raw_tracepoint",
    "btf_tracepoint",
    "uprobe",
    "uretprobe",
    "cgroup_sysctl",
    "iter",
];

/// The sources of `agent-ebpf/src`, by repository-relative path.
fn ebpf_sources() -> BTreeMap<String, String> {
    ast::tree_sources(&repo_root(), "agent-ebpf/src")
}

/// Whether the type `ty`, written in a file of imports `ix`, holds a
/// per-CPU map anywhere: plain, path-qualified, under an import's other
/// name, behind a reference, parentheses, an array, a tuple or a generic's
/// argument (the review of #546, F6, and lot 1.7b).
fn holds_per_cpu(ix: &ast::Index<'_>, ty: &syn::Type) -> bool {
    struct V<'s, 'a> {
        ix: &'s ast::Index<'a>,
        found: bool,
    }
    impl<'a> Visit<'a> for V<'_, '_> {
        fn visit_type_path(&mut self, p: &'a syn::TypePath) {
            let segs = ast::segments(&p.path);
            if self
                .ix
                .full_paths(&segs)
                .iter()
                .any(|f| PER_CPU_TYPES.contains(&f[f.len() - 1].as_str()))
            {
                self.found = true;
            }
            visit::visit_type_path(self, p);
        }
    }
    let mut v = V { ix, found: false };
    v.visit_type(ty);
    v.found
}

/// What a file declares with a per-CPU map type, by name: its `static`s
/// (`maps`), and the `type` aliases and the structs, enums and unions that
/// hold one (`hiders`: forbidden — a `static X: Alias` would hide the map
/// from this list). Every item, in modules, functions and `macro_rules!`
/// too (a static a macro declares is named by its metavariable, which no
/// row lists).
#[derive(Default)]
struct Decls {
    maps: Vec<String>,
    hiders: Vec<String>,
}

fn per_cpu_decls(c: &Corpus<'_>, rel: &str, file: &syn::File) -> Decls {
    struct V<'s, 'a> {
        ix: &'s ast::Index<'a>,
        out: Decls,
    }
    impl<'a> Visit<'a> for V<'_, '_> {
        fn visit_item_static(&mut self, s: &'a syn::ItemStatic) {
            if holds_per_cpu(self.ix, &s.ty) {
                self.out.maps.push(s.ident.to_string());
            }
            visit::visit_item_static(self, s);
        }
        fn visit_item_type(&mut self, t: &'a syn::ItemType) {
            if holds_per_cpu(self.ix, &t.ty) {
                self.out.hiders.push(t.ident.to_string());
            }
            visit::visit_item_type(self, t);
        }
        fn visit_field(&mut self, f: &'a syn::Field) {
            if holds_per_cpu(self.ix, &f.ty) {
                let name = f
                    .ident
                    .as_ref()
                    .map_or_else(|| "a field".to_string(), |i| i.to_string());
                self.out.hiders.push(format!("a type's {name}"));
            }
            visit::visit_field(self, f);
        }
    }
    let mut v = V {
        ix: &c.files[rel],
        out: Decls::default(),
    };
    v.visit_file(file);
    v.out
}

/// `(file, name)` pairs.
type Found = Vec<(String, String)>;

/// `(file, map)` of every per-CPU map declared in `sources`, and `(file,
/// hider)` of every type alias or type that holds a per-CPU map type.
fn per_cpu_maps_of(sources: &BTreeMap<String, String>) -> (Found, Found) {
    let parsed = ast::parse_all(sources, false);
    let c = Corpus::of(sources, &parsed);
    let mut out = Vec::new();
    let mut hiders = Vec::new();
    for (rel, f) in &parsed {
        let d = per_cpu_decls(&c, rel, f);
        out.extend(d.maps.into_iter().map(|n| (rel.clone(), n)));
        hiders.extend(d.hiders.into_iter().map(|n| (rel.clone(), n)));
    }
    out.sort();
    (out, hiders)
}

fn per_cpu_maps() -> (Found, Found) {
    per_cpu_maps_of(&ebpf_sources())
}

/// A program's kind, from its attributes: `lsm`, `fentry`, …, `iter` (a
/// `link_section = "iter/…"`).
fn program_kind(attrs: &[syn::Attribute]) -> Option<String> {
    for a in attrs {
        let name = ast::last(a.path());
        if KINDS.contains(&name.as_str()) {
            return Some(name);
        }
        if name == "unsafe" && ast::compact(&a.meta).contains("link_section=\"iter/") {
            return Some("iter".to_string());
        }
    }
    None
}

/// Every program of `sources` with its kind, and the maps it may reach
/// (through every function, `const` and `static` its code may run or read:
/// [`ast::Graph`]): `map → [(file, program, kind)]`.
fn programs_reaching(
    sources: &BTreeMap<String, String>,
    maps: &[String],
) -> BTreeMap<String, Vec<(String, String, String)>> {
    let parsed = ast::parse_all(sources, true);
    let c = Corpus::of(sources, &parsed);
    let g = ast::Graph::new(&c);
    let mut out: BTreeMap<String, Vec<(String, String, String)>> = BTreeMap::new();
    for (rel, f) in &parsed {
        for item in &f.items {
            let syn::Item::Fn(p) = item else {
                continue;
            };
            let Some(kind) = program_kind(&p.attrs) else {
                continue;
            };
            let name = p.sig.ident.to_string();
            let start = g.fns_named(rel, &name);
            for n in g.reach(&start).keys() {
                let words: BTreeSet<String> = ast::idents(g.tokens(n))
                    .into_iter()
                    .map(|(w, _)| w)
                    .collect();
                for m in maps {
                    let is_it = matches!(n, ast::Node::Value(_, v, _) if v == m);
                    if words.contains(m) || is_it {
                        out.entry(m.clone()).or_default().push((
                            rel.clone(),
                            name.clone(),
                            kind.clone(),
                        ));
                    }
                }
            }
        }
    }
    for v in out.values_mut() {
        v.sort();
        v.dedup();
    }
    out
}

/// Lot 1.7b: the programs of another kind that reach a map of
/// [`Why::PreemptOff`] or [`Why::SingleReader`] only through a helper both
/// share, whose argument picks the map — `(map, program, why)`. The scan
/// follows names, not values: each is listed by name, with the argument
/// that keeps it off the map, pinned below.
const REACH_KNOWN: &[(&str, &str, &str)] = &[(
    "COMMIT_ENV",
    "exec_env_lsm",
    "the environment's scan is shared with the post-commit check: `env_entry(sel, …)` takes \
     COMMIT_ENV for `sel != 0` (the tracepoint's), the LSM pass's task entry EXECPOL_ENV for \
     `sel == 0` — `nn_env_pending`'s `env_entry(0, tid, start)` and `nn_env_judge(…, 0)`, \
     pinned in the_exec_environment_is_read_by_the_exec_s_own_lsm_run",
)];

/// The programs that may reach a map whose safety rests on who runs it
/// ([`Why::PreemptOff`]: a program that runs with preemption off;
/// [`Why::SingleReader`]: an iterator, or a program of the map's own file
/// — the diagnostic mode's) and run otherwise: `(map, file, program,
/// kind)`.
fn misplaced(sources: &BTreeMap<String, String>, known: &[(&str, Why)]) -> Vec<String> {
    let (found, _) = per_cpu_maps_of(sources);
    let maps: Vec<String> = known
        .iter()
        .filter(|(_, w)| matches!(w, Why::PreemptOff | Why::SingleReader))
        .map(|(m, _)| m.to_string())
        .collect();
    let reach = programs_reaching(sources, &maps);
    let mut out = Vec::new();
    for (m, why) in known {
        let home = found.iter().find(|(_, n)| n == m).map(|(f, _)| f.as_str());
        for (rel, prog, kind) in reach.get(*m).into_iter().flatten() {
            let fine = match why {
                Why::PreemptOff => PREEMPT_OFF.contains(&kind.as_str()),
                Why::SingleReader => kind == "iter" || Some(rel.as_str()) == home,
                _ => true,
            };
            let listed = REACH_KNOWN.iter().any(|(km, kp, _)| km == m && kp == prog);
            if !fine && !listed {
                out.push(format!("{m} ({why:?}) reached by {rel} {prog} (#[{kind}])"));
            }
        }
    }
    out
}

/// The review of #546 (F6), as Rust (lot 1.7b): the scanner sees a per-CPU
/// map however it is declared — plain, path-qualified, through a type
/// alias, under an import's other name, in parentheses, an array, a
/// generic's argument, a struct's field — and nothing else. Planted in the
/// scanner's own input.
#[test]
fn the_scanner_sees_every_spelling_of_a_per_cpu_map() {
    let planted = "
        use aya_ebpf::maps::PerCpuArray as Buf;
        static PLAIN: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
        pub(crate) static QUALIFIED: aya_ebpf::maps::PerCpuArray<[u8; 8]> = x;
        static HASHED: aya_ebpf::maps::per_cpu_hash_map::PerCpuHashMap<u32, u64> = x;
        static LRU: LruPerCpuHashMap<u32, u64> = x;
        type Scratch = aya_ebpf::maps::PerCpuArray<[u8; 64]>;
        static SNEAKY: Scratch = x;
        static RENAMED: Buf<u64> = x;
        static PARENS: (PerCpuArray<u64>) = x;
        static mut TURBOFISH: PerCpuArray::<u64> = x;
        static TWO: [PerCpuArray<u64>; 2] = x;
        static WRAPPED: Wrap<PerCpuArray<u64>> = x;
        struct Holder { buf: PerCpuArray<u64> }
        static FINE: HashMap<TaskKey, u64> = x;
        static ALSO_FINE: LruHashMap<u64, u64> = x;
        static ARRAY: Array<u64> = x;
    ";
    let rel = "agent-ebpf/src/planted.rs".to_string();
    let sources: BTreeMap<String, String> = [(rel.clone(), planted.to_string())].into();
    let (maps, hiders) = per_cpu_maps_of(&sources);
    let names: Vec<&str> = maps.iter().map(|(_, n)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "HASHED",
            "LRU",
            "PARENS",
            "PLAIN",
            "QUALIFIED",
            "RENAMED",
            "TURBOFISH",
            "TWO",
            "WRAPPED"
        ]
    );
    let hiders: Vec<&str> = hiders.iter().map(|(_, n)| n.as_str()).collect();
    assert_eq!(hiders, ["Scratch", "a type's buf"]);
}

/// Every per-CPU map is classified, the list names no map that is gone,
/// and no type alias or type hides one. A new per-CPU buffer kept across a
/// helper call in an LSM, fentry or iterator program fails here: make it the
/// running task's own entry (`agent-ebpf/src/task_scratch.rs`), or say why
/// it is safe. Lot 1.7b (the review of #546's "a classification is not tied
/// to a program type"): a map safe because of who runs it is reached by
/// such programs only.
#[test]
fn every_per_cpu_map_is_safe_across_preemption_or_listed() {
    let (found, aliases) = per_cpu_maps();
    assert!(
        aliases.is_empty(),
        "a type alias or a type holding a per-CPU map type (it would hide the map from this \
         list): {aliases:?}"
    );
    let unknown: Vec<String> = found
        .iter()
        .filter(|(_, m)| !KNOWN.iter().any(|(k, _)| k == m))
        .map(|(f, m)| format!("{f}: {m}"))
        .collect();
    assert!(
        unknown.is_empty(),
        "per-CPU maps nobody classified (a buffer kept across a helper call by a preemptible \
         program is rewritten by another task's run on the same CPU): {unknown:#?}"
    );
    let stale: Vec<&str> = KNOWN
        .iter()
        .filter(|(k, _)| !found.iter().any(|(_, m)| m == k))
        .map(|(k, _)| *k)
        .collect();
    assert!(stale.is_empty(), "listed but gone: {stale:?}");
    // the FIM sensor's buffers are no longer per CPU
    for gone in ["OPEN_SCRATCH", "OPEN_WIN", "RENAME_SCRATCH", "RENAME_EXT"] {
        assert!(!found.iter().any(|(_, m)| m == gone), "{gone}");
    }
    let wrong = misplaced(&ebpf_sources(), KNOWN);
    assert!(
        wrong.is_empty(),
        "a per-CPU map safe only in the programs its row names, reached by another: {wrong:#?}"
    );
    let maps: Vec<String> = REACH_KNOWN.iter().map(|(m, _, _)| m.to_string()).collect();
    let reach = programs_reaching(&ebpf_sources(), &maps);
    for (m, prog, why) in REACH_KNOWN {
        assert!(why.len() > 40, "{m} {prog}: say why");
        assert!(
            reach
                .get(*m)
                .into_iter()
                .flatten()
                .any(|(_, p, _)| p == prog),
            "{m} {prog}: listed in REACH_KNOWN, no longer reached"
        );
    }
}

/// Lot 1.7b: a `PreemptOff` buffer reached from an LSM program — through a
/// helper of its file — or a `SingleReader` one from a program of another
/// file fails; the programs that reach each today are of their kind.
#[test]
fn a_per_cpu_buffer_reached_from_a_preemptible_program_is_caught() {
    let sources = ebpf_sources();
    assert!(misplaced(&sources, KNOWN).is_empty());
    let mut lsm = sources.clone();
    lsm.get_mut("agent-ebpf/src/stdio.rs").unwrap().push_str(
        "\n#[lsm(hook = \"file_open\")]\npub fn planted_open(ctx: LsmContext) -> i32 {\n    \
         planted_peek()\n}\n\nfn planted_peek() -> i32 {\n    \
         unsafe { STDIO_SCRATCH.get_ptr(0) }.is_some() as i32\n}\n",
    );
    let v = misplaced(&lsm, KNOWN);
    assert!(
        v.iter().any(|l| l.contains(
            "STDIO_SCRATCH (PreemptOff) reached by agent-ebpf/src/stdio.rs planted_open (#[lsm])"
        )),
        "{v:#?}"
    );
    let mut other = sources.clone();
    other.get_mut("agent-ebpf/src/exec_lsm.rs").unwrap().push_str(
        "\n#[fentry(function = \"do_exit\")]\npub fn planted_exit(ctx: FEntryContext) -> i32 {\n    \
         unsafe { crate::sensor_probe::PROBE_SCRATCH.get_ptr(0) }.is_some() as i32\n}\n",
    );
    let v = misplaced(&other, KNOWN);
    assert!(
        v.iter().any(|l| l.contains("PROBE_SCRATCH (SingleReader) reached by agent-ebpf/src/exec_lsm.rs planted_exit (#[fentry])")),
        "{v:#?}"
    );
}

/// Lot 1.7b: the spellings the lexical scan missed, each planted in a copy
/// of `exec_lsm.rs`: the lexical scan finds the same maps and aliases, the
/// AST scan one more — a map under an import's other name, in parentheses,
/// with a turbofish, in an array, as a generic's argument, a struct's field
/// holding one.
#[test]
fn the_lexical_bypasses_are_caught() {
    let host = "agent-ebpf/src/exec_lsm.rs";
    let text = fs::read_to_string(repo_root().join(host)).unwrap();
    let count = |t: &str| {
        let one: BTreeMap<String, String> = [(host.to_string(), t.to_string())].into();
        let (m, a) = per_cpu_maps_of(&one);
        m.len() + a.len()
    };
    let lex = |t: &str| {
        let (m, a) = lexical::per_cpu_decls(&strip_comments(t));
        m.len() + a.len()
    };
    let (base_lex, base) = (lex(&text), count(&text));
    for plant in [
        "use aya_ebpf::maps::PerCpuArray as Buf;\nstatic PLANTED: Buf<u64> = Buf::with_max_entries(1, 0);",
        "static PLANTED: (PerCpuArray<u64>) = PerCpuArray::with_max_entries(1, 0);",
        "static PLANTED: aya_ebpf::maps::PerCpuArray::<u64> = PerCpuArray::with_max_entries(1, 0);",
        "static PLANTED: [PerCpuArray<u64>; 1] = [PerCpuArray::with_max_entries(1, 0)];",
        "static PLANTED: Wrap<PerCpuArray<u64>> = Wrap(PerCpuArray::with_max_entries(1, 0));",
        "struct Planted {\n    buf: PerCpuArray<u64>,\n}",
    ] {
        let copy = format!("{text}\n{plant}\n");
        assert_eq!(lex(&copy), base_lex, "the lexical scan saw it: {plant}");
        assert_eq!(count(&copy), base + 1, "{plant}");
    }
}

/// The exec guards' and the FIM sensor's buffers are the running task's
/// own entries, made at the start of the run and removed before it
/// returns: the exec sensor's walk (the classes the exec policy refuses
/// on), the environment, the mapping check's walk, the quarantine's
/// candidate, the BPF guard's `OBJ_GET` path, the FIM sensor's windows and
/// names, a rename's names. They were per-CPU buffers in preemptible
/// programs. The review of #546 (F4): plain hashes, never an LRU (whose
/// insert can evict an entry in flight and hand its memory to another
/// task), with a cap whose overflow fails closed.
#[test]
fn the_exec_guards_buffers_are_the_running_task_s_own() {
    let lsm = code("agent-ebpf/src/exec_lsm.rs");
    let pol = code("agent-ebpf/src/execpol.rs");
    let q = code("agent-ebpf/src/execq.rs");
    let bpf = code("agent-ebpf/src/bpf_defense.rs");
    let open = code("agent-ebpf/src/open_sensor.rs");
    let fim = code("agent-ebpf/src/fim_watch.rs");
    let cap = "HashMap::with_max_entries(crate::task_scratch::TASK_SCRATCH_CAP, 0);";
    // lot 1.7b: each found as Rust, its type and initialiser whole, its
    // `HashMap` aya's plain hash through the file's imports
    for (rel, name, ty) in [
        (
            "exec_lsm.rs",
            "EXEC_SCRATCH",
            "HashMap<TaskKey, ExeIdentityRaw>",
        ),
        ("execpol.rs", "EXECPOL_ENV", "HashMap<TaskKey, EnvScan>"),
        (
            "execpol.rs",
            "EXECMAP_SCRATCH",
            "HashMap<TaskKey, ExeIdentityRaw>",
        ),
        (
            "execq.rs",
            "EXECQ_CAND_SCRATCH",
            "HashMap<TaskKey, ExecqCandRaw>",
        ),
        (
            "bpf_defense.rs",
            "OBJ_GET_PATH_SCRATCH",
            "HashMap<TaskKey, [u8; PATH_BUF_LEN]>",
        ),
        ("open_sensor.rs", "RENAME_TASK", "HashMap<u64, RenameTask>"),
    ] {
        assert_task_map(
            &format!("agent-ebpf/src/{rel}"),
            name,
            ty,
            cap.trim_end_matches(';'),
        );
    }
    // Lot 325 (cost): the FIM sensor's entry lives as long as its task — a
    // plain hash still, allocated as tasks come, removed at `task_free`
    assert_task_map(
        "agent-ebpf/src/open_sensor.rs",
        "OPEN_TASK",
        "HashMap<u64, OpenTask>",
        "HashMap::with_max_entries(OPEN_TASK_CAP, crate::task_scratch::BPF_F_NO_PREALLOC)",
    );
    let ts = code("agent-ebpf/src/task_scratch.rs");
    assert!(
        !ts.contains("LruHashMap"),
        "task_scratch.rs makes LRU entries"
    );
    in_order(
        &ts,
        &[
            "pub(crate) unsafe fn make<K, T>(map: &HashMap<K, T>, key: &K) -> Option<*mut T> {",
            "map.insert(key, &*(zero as *const T), 0).ok()?;",
            "map.get_ptr_mut(key)",
        ],
    )
    .unwrap();
    // the candidate: built in the task's own buffer, then copied
    in_order(
        body(&q, "note_pass"),
        &[
            "crate::task_scratch::make(&EXECQ_CAND_SCRATCH, &ck)",
            "crate::execpol::count_lost();",
            "let _ = nn_execq_cand_put(task, u64::from(ck.tid), ck.start_ns);",
        ],
    )
    .unwrap();
    in_order(
        body(&q, "nn_execq_cand_put"),
        &[
            "EXECQ_CAND_SCRATCH.get_ptr_mut(&ck)",
            "cand_put(task, cand);",
            "let _ = EXECQ_CAND_SCRATCH.remove(&ck);",
        ],
    )
    .unwrap();
    // copied into the candidates' map within the login's share (the review
    // of #547, F4; the re-check, G5), the share given back when it goes;
    // the map full, the oldest candidate goes for it (counted)
    in_order(
        body(&q, "cand_put"),
        &[
            "cand_take(task);",
            "crate::task_scratch::share_take(",
            "&EXECQ_CAND_UIDS,",
            "&EXECQ_CAND_OVERFLOW,",
            "crate::task_scratch::share_key(),",
            "EXECQ_CAND_PER_SHARE,",
            "EXECQ_CAND_GLOBAL,",
            "EXECQ_CAND_FLOOR,",
            "bump(counter::CAND_DROPPED);",
            "(*cand).uid = row;",
            "(*cand).at = now;",
            "if EXECQ_CAND.insert(&task, &*cand, 0).is_err() {",
            "if !(evict_oldest(now) && EXECQ_CAND.insert(&task, &*cand, 0).is_ok()) {",
            "crate::task_scratch::share_give(&EXECQ_CAND_UIDS, &EXECQ_CAND_OVERFLOW, row);",
            "bump(counter::CAND_DROPPED);",
            "bump(counter::CAND_EVICTED);",
        ],
    )
    .unwrap();
    // lot 332 (the re-check 2 of #547, G5): the oldest found by walking
    // the map itself, every entry — no ring that failed execs could fill
    // with gone candidates
    in_order(
        body(&q, "evict_oldest"),
        &[
            "generated::bpf_for_each_map_elem(",
            "&EXECQ_CAND as *const HashMap<u64, ExecqCandRaw> as *mut c_void,",
            "oldest_candidate as *const () as *mut c_void,",
            "&mut o as *mut Oldest as *mut c_void,",
            "if o.task == 0 {",
            "return false;",
            "Some(c) => c.at == o.at,",
            "if same {",
            "cand_take(o.task);",
            "true",
        ],
    )
    .unwrap();
    in_order(
        body(&q, "oldest_candidate"),
        &[
            "let at = (*value).at;",
            "if now > at && now - at >= EVICT_MIN_AGE_NS && ((*ctx).task == 0 || at < (*ctx).at) {",
            "(*ctx).task = *key;",
            "(*ctx).at = at;",
            "0",
        ],
    )
    .unwrap();
    for gone in [
        "EXECQ_CAND_RING",
        "EXECQ_CAND_HEAD",
        "EVICT_PROBES",
        "ring_note",
    ] {
        assert!(!q.contains(gone), "{gone}: the eviction walks the map");
    }
    assert!(body(&q, "cand_remove").contains("let _ = nn_execq_cand_remove(task);"));
    assert!(body(&q, "nn_execq_cand_remove").contains("cand_take(task);"));
    assert!(body(&q, "forget_freed").contains("cand_take(task);"));
    in_order(
        body(&q, "cand_take"),
        &[
            "EXECQ_CAND.remove(&task).is_ok()",
            "crate::task_scratch::share_give(&EXECQ_CAND_UIDS, &EXECQ_CAND_OVERFLOW, uid);",
        ],
    )
    .unwrap();
    // the exec sensor: made, walked by key, judged, removed
    in_order(
        body(&lsm, "try_exec_check_lsm"),
        &[
            "let key = crate::task_scratch::key_of(task);",
            "crate::task_scratch::make(&EXEC_SCRATCH, &key)",
            // the map full: judged without the walk (lot 325, R5: the
            // protected targets refused, the rest let through, counted)
            "crate::execpol::nn_exec_unwalked(",
            "return if refuse != 0 { -13 } else { 0 };",
            "nn_exe_walk(",
            "crate::execpol::on_pass(s, inode, dentry, task as u64, pass, &key);",
            "let _ = EXEC_SCRATCH.remove(&key);",
        ],
    )
    .unwrap();
    assert!(
        body(&lsm, "nn_exe_walk")
            .contains("EXEC_SCRATCH.get_ptr_mut(&crate::task_scratch::key(tid, start))")
    );
    assert!(
        body(&q, "nn_execq_classify")
            .contains("EXEC_SCRATCH.get_ptr(&crate::task_scratch::key(tid, start))")
    );
    // a walk gone is classed as one that could not place the file
    assert!(
        body(&q, "nn_execq_classify")
            .contains("None => u64::from(class::TMP | class::VAR_TMP | class::HOME),")
    );
    in_order(
        body(&pol, "exec_unwalked"),
        &[
            "let refuse = m == mode::ENFORCE && deny_c != 0;",
            "if refuse {",
            "bump(counter::LOST);",
            "} else {",
            "bump(counter::LOST_OPEN);",
        ],
    )
    .unwrap();
    // the mapping check: the walk made per task, removed on every way out,
    // and walked again for a report from the cache
    in_order(
        body(&pol, "execmap_check"),
        &[
            "let rc = try_execmap(&ctx, task, &mut walked);",
            "let _ = EXECMAP_SCRATCH.remove(k);",
        ],
    )
    .unwrap();
    in_order(
        body(&pol, "try_execmap"),
        &[
            "if cached {",
            "*walked = Some(wk);",
            "nn_map_classify(file as u64, u64::from(wk.tid), wk.start_ns);",
            "EXECMAP_SCRATCH.get_ptr(&wk)",
        ],
    )
    .unwrap();
    assert!(body(&pol, "map_classify").contains("crate::task_scratch::make(&EXECMAP_SCRATCH"));
    // no walk: counted, classed as a file the walk cannot place, not cached
    in_order(
        body(&pol, "map_classify"),
        &[
            "bump(counter::LOST);",
            "return MAP_WALK_LOST | class::TMP | class::VAR_TMP | class::HOME;",
        ],
    )
    .unwrap();
    in_order(
        body(&pol, "try_execmap"),
        &[
            "classes = r & !MAP_WALK_LOST;",
            "if r & MAP_WALK_LOST == 0 {",
            "EXECMAP_SEEN.insert",
        ],
    )
    .unwrap();
    // the BPF guard's path buffer
    in_order(
        body(&bpf, "nn_obj_get_own_link"),
        &[
            "crate::task_scratch::make(&OBJ_GET_PATH_SCRATCH, &key)",
            "obj_get_names_own_link(user_ptr, buf)",
            "let _ = OBJ_GET_PATH_SCRATCH.remove(&key);",
        ],
    )
    .unwrap();
    // the FIM sensor (the review of #546, F3): the open's windows and names,
    // a rename's names and extensions, each the running task's, removed at
    // the end of the run; the map full: the plain observer, counted
    in_order(
        body(&open, "on_open"),
        &[
            "match task_buffer(task) {",
            "crate::drops::bump(northnarrow_common::ring_drops::ring_slot::OPEN_SENSOR);",
            "crate::fim_watch::observe_open_plain(file);",
            "on_open_in(file, t, task, live);",
            // lot 325: kept for the task's life when `task_free` removes
            // it; the review of #547 (F6): else the run's own, removed
            "if !live {",
            "let _ = OPEN_TASK_RUN.remove(&task);",
        ],
    )
    .unwrap();
    assert!(body(&open, "on_open_in").contains("nn_open_observe(") && !open.contains("OPEN_WIN"));
    // lot 332: the global functions past the watch find the task's buffer
    // again by its key, in the map `on_open` found it in
    in_order(
        body(&open, "buffer_of"),
        &[
            "if dev_bits >> OBS_LIVE & 1 != 0 {",
            "OPEN_TASK.get_ptr_mut(&task)",
            "OPEN_TASK_RUN.get_ptr_mut(&task)",
        ],
    )
    .unwrap();
    assert!(body(&open, "walk").contains("match task_buffer(task) {"));
    let tb = body(&open, "task_buffer");
    assert!(tb.contains("if nn_open_task_make(task) != 0 {"));
    assert!(
        body(&open, "nn_open_task_make").contains("crate::task_scratch::make(&OPEN_TASK, &task)")
    );
    assert!(tb.contains("crate::task_scratch::make(&OPEN_TASK_RUN, &task)"));
    assert_task_map(
        "agent-ebpf/src/open_sensor.rs",
        "OPEN_TASK_RUN",
        "HashMap<u64, OpenTask>",
        "HashMap::with_max_entries(crate::task_scratch::TASK_SCRATCH_CAP, 0)",
    );
    in_order(
        body(&open, "nn_rename_burst"),
        &["rename_burst(", "let _ = RENAME_TASK.remove(&task);"],
    )
    .unwrap();
    assert!(body(&open, "rename_burst").contains("crate::task_scratch::make(&RENAME_TASK, &task)"));
    for f in ["nn_rename_ext", "nn_rename_shape"] {
        assert!(body(&open, f).contains("RENAME_TASK.get_ptr"), "{f}");
    }
    for f in ["try_fim_unlink_observe", "try_fim_rename_observe"] {
        let b = body(&fim, f);
        in_order(
            b,
            &["nn_unlink_burst(", "crate::open_sensor::forget_task();"],
        )
        .unwrap();
    }
    // the key: thread id and start time, so a reused id inherits nothing
    let ts = code("agent-ebpf/src/task_scratch.rs");
    in_order(
        body(&ts, "key_of"),
        &[
            "TASK_STRUCT_START_TIME_OFFSET",
            "start_ns:",
            "tid: bpf_get_current_pid_tgid() as u32",
        ],
    )
    .unwrap();
}

/// The bug of lot 322: no exec decision rests on a syscall tracepoint. The
/// environment is read at the exec's first pass by the exec sensor's LSM
/// program, from `envp` as the exec's own registers hold it (`execve`'s
/// `dx`, `execveat`'s `r10`), scanned into the task's own entry, judged on
/// the findings the scan returned, and the entry removed in the same run.
#[test]
fn the_exec_environment_is_read_by_the_exec_s_own_lsm_run() {
    let pol = code("agent-ebpf/src/execpol.rs");
    // Lot 325: one tracepoint program, the post-commit check, on
    // `sched_process_exec` — a tracepoint that is no syscall's, which runs
    // on every CPU; nothing of execpol.rs on a syscall tracepoint.
    assert_eq!(
        pol.matches("#[tracepoint]").count(),
        1,
        "tracepoint programs in execpol.rs"
    );
    assert!(pol.contains("#[tracepoint]\npub fn execpol_env_commit("));
    // lot 1.7b, as Rust: the one tracepoint program however its attribute
    // is spelt (`#[tracepoint(…)]`, a path), and no program of the file on
    // a raw or BTF tracepoint either
    let programs = programs_of("agent-ebpf/src/execpol.rs");
    let tp: Vec<&(String, String)> = programs
        .iter()
        .filter(|(_, k)| k.contains("tracepoint"))
        .collect();
    assert_eq!(
        tp,
        [&("execpol_env_commit".to_string(), "tracepoint".to_string())],
        "tracepoint programs in execpol.rs"
    );
    let m = code("agent/src/execpol/mod.rs");
    assert!(m.contains("prog.attach(\"sched\", \"sched_process_exec\")"));
    assert!(
        !m.contains("\"syscalls\""),
        "an execpol program on a syscall tracepoint"
    );
    // lot 1.7b: … nor through a constant, a `concat!` or a `format!` —
    // every `attach` of the file, by the values its arguments can hold
    let on_syscalls = syscall_attaches("agent/src/execpol/mod.rs");
    assert!(
        on_syscalls.is_empty(),
        "an execpol program on a syscall tracepoint: {on_syscalls:?}"
    );
    assert!(!pol.contains("EXECPOL_ENV_SCRATCH"));
    assert!(!pol.contains("TP_SYS_ENTER_EXECVE"));
    // the re-check of #547 (G6): by the environment's own LSM program on
    // the exec sensor's hook (`exec_env_lsm`), its first pass
    let p = body(&pol, "try_exec_env_lsm");
    in_order(
        p,
        &[
            "let er = nn_exec_env(task, u64::from(wk.tid), wk.start_ns);",
            "if ef == 0 {",
            "let stashed = er & ENV_STASHED != 0;",
            "if (ef & env_flags::DENYABLE != 0 && env_deny_rule) || unfinished {",
            "nn_env_report(",
            "if stashed {",
            "let _ = EXECPOL_ENV.remove(&wk);",
        ],
    )
    .unwrap();
    assert!(!body(&pol, "on_pass").contains("nn_exec_env("));
    in_order(
        body(&pol, "exec_envp"),
        &[
            "off_opt!(PT_REGS_ORIG_AX_OFFSET)",
            "TASK_STRUCT_MM_OFFSET",
            "regs_are_the_writes(tflags)",
            "bpf_task_pt_regs(generated::bpf_get_current_task_btf())",
            "let (reg, abi) = match exec_envp_reg(nr) {",
            "None => return ENVP_UNREAD,",
            "EnvpReg::Dx => off_opt!(PT_REGS_DX_OFFSET),",
            "EnvpReg::R10 => off_opt!(PT_REGS_R10_OFFSET),",
            "EnvpReg::Si => off_opt!(PT_REGS_SI_OFFSET),",
            "envp_value(peek_u64((regs + off as u64) as *const u8), abi)",
            "if abi.compat_pointers() {",
            "v | ENVP_COMPAT",
        ],
    )
    .unwrap();
    // the review of #546 (F1, F2): a compat call's array of 32-bit
    // pointers is read; an entry or a string the scan cannot read is a
    // finding (never skipped), counted and recorded, never refused
    in_order(
        body(&pol, "nn_env_step"),
        &[
            "let stride = envp_stride(compat);",
            "stride as u32,",
            "(envp + (idx + i as u64) * stride)",
            "return i as u64 | UNREAD;",
            ") < 0",
            "unread = UNREAD;",
        ],
    )
    .unwrap();
    in_order(
        body(&pol, "env_scan"),
        &[
            "if r & UNREAD != 0 {",
            "(*e).stash.flags |= env_flags::UNREADABLE;",
        ],
    )
    .unwrap();
    assert!(body(&pol, "nn_env_var").contains("(*e).stash.flags |= env_flags::UNREADABLE;"));
    let so = body(&pol, "scan_one");
    assert_eq!(
        so.matches("st.flags |= env_flags::UNREADABLE;").count(),
        5,
        "each captured value's read failure is flagged:\n{so}"
    );
    in_order(
        body(&pol, "exec_env"),
        &[
            "if raw == ENVP_UNREAD {",
            "return u64::from(env_flags::UNREADABLE);",
            "let compat = raw >> 63;",
            "env_scan(envp, u64::from(key.tid), key.start_ns, compat)",
            "if r & SCAN_LOST != 0 {",
            "return u64::from(env_flags::UNREADABLE);",
            "u64::from(ef) | ENV_STASHED",
        ],
    )
    .unwrap();
    let p = body(&pol, "try_exec_env_lsm");
    in_order(
        p,
        &[
            "if ef & env_flags::UNREADABLE != 0 {",
            "bump(counter::ENV_UNREAD);",
            "| env_flags::UNREADABLE",
            // lot 325 (R2): and one the scan could not finish
            "| env_flags::UNFINISHED",
            // the review of #547 (F1): and a relative loader path
            "| env_flags::PRELOAD_RELATIVE",
            // the re-check of #547 (G1–G4): and an irregular loader value
            "| env_flags::LOADER_IRREGULAR)",
        ],
    )
    .unwrap();
    assert!(
        !p.contains("UNREADABLE) != 0 {\n                if m == mode::ENFORCE"),
        "an unread environment is never refused"
    );
    // the agent reports both counters
    let m = code("agent/src/execpol/mod.rs");
    assert!(m.contains("s(&self.env_unread, counter::ENV_UNREAD);"));
    assert!(m.contains("s(&self.lost, counter::LOST);"));
    in_order(
        body(&pol, "env_scan"),
        &[
            "crate::task_scratch::make(&EXECPOL_ENV, &key)",
            "nn_env_round(",
            "if f == 0 {",
            "EXECPOL_ENV.remove(&key)",
        ],
    )
    .unwrap();
    // The review of #547 (F1): each loader value judged whole in the task's
    // entry. An entry gone under the judgment (lot 322: it counted as
    // staging) stops the scan unfinished — `TRUNCATED`, refused at a
    // protected or set-id target — never a clean environment.
    assert!(
        body(&pol, "nn_env_pending")
            .contains("nn_env_judge(nn_env_var(ptr, tid, start, 0), ptr, tid, start, 0);")
    );
    in_order(
        body(&pol, "nn_env_pending"),
        &[
            "None => return STOP,",
            "nn_env_judge(",
            "if env_entry(0, tid, start).is_none() {",
            "return STOP;",
        ],
    )
    .unwrap();
    in_order(
        body(&pol, "env_scan"),
        &[
            "if nn_env_pending(tid, start) & STOP != 0 {",
            "(*e).stash.flags |= env_flags::TRUNCATED;",
            "let f = nn_env_resolve(0, tid, start) as u32;",
        ],
    )
    .unwrap();
    // the record carries the findings the judgment rested on
    assert!(body(&pol, "report_exec").contains("(*raw).env_flags = ef;"));
    // nothing in the agent attaches a program to the exec syscalls for it;
    // it arms the check when the four registers' offsets resolved
    let m = code("agent/src/execpol/mod.rs");
    assert!(!m.contains("sys_enter_execve"), "agent/src/execpol/mod.rs");
    // (the re-check of #547, G6: and attaches the environment's program)
    assert!(m.contains("if !offsets_resolved(&ENV_OFFSETS) {"));
    assert!(m.contains("} else if let Err(e) = attach_env_lsm(ebpf) {"));
    let flat = m.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(flat.contains(
        "pub const ENV_OFFSETS: [u32; 4] = [ common::btf_offsets::slot::PT_REGS_ORIG_AX_OFFSET, \
         common::btf_offsets::slot::PT_REGS_DX_OFFSET, \
         common::btf_offsets::slot::PT_REGS_R10_OFFSET, \
         common::btf_offsets::slot::PT_REGS_SI_OFFSET, ];"
    ));
}

/// The programs of `rel`, as Rust: `(name, kind)` ([`program_kind`]).
fn programs_of(rel: &str) -> Vec<(String, String)> {
    programs_in(rel, &code(rel))
}

/// [`programs_of`] `text`, read as the file `rel`.
fn programs_in(rel: &str, text: &str) -> Vec<(String, String)> {
    let one: BTreeMap<String, String> = [(rel.to_string(), text.to_string())].into();
    let parsed = ast::parse_all(&one, true);
    let mut out = Vec::new();
    for item in &parsed[rel].items {
        if let syn::Item::Fn(f) = item {
            if let Some(k) = program_kind(&f.attrs) {
                out.push((f.sig.ident.to_string(), k));
            }
        }
    }
    out
}

/// The `attach` calls of `rel` (production code) whose arguments can hold a
/// syscall tracepoint (`syscalls`, `sys_enter_…`, `sys_exit_…`), by line.
fn syscall_attaches(rel: &str) -> Vec<usize> {
    let one: BTreeMap<String, String> = [(rel.to_string(), code(rel))].into();
    let parsed = ast::parse_all(&one, true);
    let c = Corpus::of(&one, &parsed);
    let ix = &c.files[rel];
    ix.calls
        .iter()
        .filter(|call| call.name == "attach")
        .filter(|call| {
            call.args.iter().any(|a| {
                c.values(rel, a, call.scope).iter().any(|v| {
                    v.contains("syscalls") || v.contains("sys_enter_") || v.contains("sys_exit_")
                })
            })
        })
        .map(|call| call.line)
        .collect()
}

/// The scan before lot 1.7b (lexical: `static NAME:` and its type's head,
/// `type NAME =`), kept only to show the spellings it missed.
mod lexical {
    /// The per-CPU map types of aya-ebpf.
    const PER_CPU_TYPES: [&str; 3] = ["PerCpuArray<", "PerCpuHashMap<", "LruPerCpuHashMap<"];

    /// Whether the type text `ty` (after `static NAME:`) is a per-CPU map,
    /// however it is spelt: plain (`PerCpuArray<…>`) or path-qualified
    /// (`aya_ebpf::maps::PerCpuArray<…>`; the review of #546, F6).
    fn is_per_cpu_type(ty: &str) -> bool {
        let head = ty.split('<').next().unwrap_or("");
        let last = head.rsplit("::").next().unwrap_or("").trim();
        PER_CPU_TYPES
            .iter()
            .any(|t| t.trim_end_matches('<') == last)
    }

    /// The names of the per-CPU maps `src` (comments stripped) declares, and
    /// the type aliases it declares to any per-CPU map type (forbidden: a
    /// `static X: Alias` would hide one; the review of #546, F6).
    pub fn per_cpu_decls(src: &str) -> (Vec<String>, Vec<String>) {
        let flat = src.split_whitespace().collect::<Vec<_>>().join(" ");
        let mut maps = Vec::new();
        for piece in flat.split("static ").skip(1) {
            let Some((name, rest)) = piece.split_once(':') else {
                continue;
            };
            if is_per_cpu_type(rest.trim_start()) {
                maps.push(name.trim().to_string());
            }
        }
        let mut aliases = Vec::new();
        for piece in flat.split("type ").skip(1) {
            let Some((name, rest)) = piece.split_once('=') else {
                continue;
            };
            let rhs = rest.split(';').next().unwrap_or("");
            if PER_CPU_TYPES
                .iter()
                .any(|t| rhs.contains(t.trim_end_matches('<')))
            {
                aliases.push(name.trim().to_string());
            }
        }
        (maps, aliases)
    }
}
