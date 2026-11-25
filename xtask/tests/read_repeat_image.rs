//! Lot 1.4 (plan S1, F7; the review of #587, P2): the read-repeat filter of
//! the `file_open` hook (review 75, `agent-ebpf/src/read_repeat.rs`) keys a
//! read-only open by the task AND its image.
//!
//! The readers of a credential file are judged by the file the kernel
//! executed. Keyed by the task alone (`pid_tgid`, `start_time`, which an
//! exec keeps), a process that read a file and then executed another
//! program in its place had that program's read of the same file within
//! the second dropped as a repeat: no record under the program that read.
//! The key now carries the task's `mm` (a new one at every exec, made while
//! the old one is still in use) and its executable's inode
//! (`mm->exe_file->f_inode`, which keeps two programs apart when an exec
//! is handed the previous image's `mm` again).
//!
//! The behaviour is shown in the lab by
//! `agent/tests/fim_privileged_e2e.rs`'s
//! `fim_cred_read_after_an_exec_gets_its_own_record`. Here the code is
//! read (with `syn`): the key's words, where each word of the image comes
//! from, and that the sensor's two judgements go through the filter's one
//! global function, each on its own map. Each rule is shown failing on a
//! planted violation.

mod support;

use std::fs;

use support::{ast, repo_root};
use syn::visit::Visit;

const READ_REPEAT: &str = "agent-ebpf/src/read_repeat.rs";
const OPEN_SENSOR: &str = "agent-ebpf/src/open_sensor.rs";
const FIM_WATCH: &str = "agent-ebpf/src/fim_watch.rs";

fn source(rel: &str) -> String {
    fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// The words of the key, in order, each a `u64`.
const KEY: [&str; 6] = ["pid_tgid", "start_time", "mm", "exe_inode", "dev", "ino"];

/// What each word of the key is built from in `repeat` (tokens, spaces
/// dropped; a name bound by a `let` of the body is replaced by its value):
/// the task, its image, then the file.
const KEY_FROM: [(&str, &str); 6] = [
    ("pid_tgid", "bpf_get_current_pid_tgid()"),
    (
        "start_time",
        "peek(bpf_get_current_task()+__macro__off(TASK_STRUCT_START_TIME_OFFSET)asu64)",
    ),
    (
        "mm",
        "peek(bpf_get_current_task()+__macro__off(TASK_STRUCT_MM_OFFSET)asu64)",
    ),
    (
        "exe_inode",
        "peek(peek(peek(bpf_get_current_task()+__macro__off(TASK_STRUCT_MM_OFFSET)asu64)\
         +__macro__off(MM_STRUCT_EXE_FILE_OFFSET)asu64)+__macro__off(FILE_F_INODE_OFFSET)asu64)",
    ),
    ("dev", "key.dev"),
    ("ino", "key.ino"),
];

fn item_fn<'a>(file: &'a syn::File, name: &str) -> Option<&'a syn::ItemFn> {
    file.items.iter().find_map(|i| match i {
        syn::Item::Fn(f) if f.sig.ident == name => Some(f),
        _ => None,
    })
}

/// The `let` bindings of a body (a plain name each), as compact tokens.
#[derive(Default)]
struct Lets(Vec<(String, String)>);

impl<'ast> Visit<'ast> for Lets {
    fn visit_local(&mut self, l: &'ast syn::Local) {
        if let (syn::Pat::Ident(p), Some(init)) = (&l.pat, &l.init) {
            self.0.push((p.ident.to_string(), ast::compact(&init.expr)));
        }
        syn::visit::visit_local(self, l);
    }
}

/// The struct literals `ReadSeenKey { … }` of a body: their fields, as
/// compact tokens.
#[derive(Default)]
struct KeyLiterals(Vec<Vec<(String, String)>>);

impl<'ast> Visit<'ast> for KeyLiterals {
    fn visit_expr_struct(&mut self, e: &'ast syn::ExprStruct) {
        if ast::last(&e.path) == "ReadSeenKey" {
            self.0.push(
                e.fields
                    .iter()
                    .map(|f| {
                        let name = match &f.member {
                            syn::Member::Named(i) => i.to_string(),
                            syn::Member::Unnamed(i) => i.index.to_string(),
                        };
                        (name, ast::compact(&f.expr))
                    })
                    .collect(),
            );
        }
        syn::visit::visit_expr_struct(self, e);
    }
}

/// `expr` with each name of `lets` (bound before) replaced by its value,
/// the last binding first, until none is left.
fn resolve(expr: &str, lets: &[(String, String)]) -> String {
    let mut out = expr.to_string();
    for _ in 0..8 {
        let mut changed = false;
        for (name, value) in lets.iter().rev() {
            let replaced = replace_ident(&out, name, value);
            if replaced != out {
                out = replaced;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    out
}

/// `name` as a whole identifier in `s` (not a field after a `.`), replaced.
fn replace_ident(s: &str, name: &str, value: &str) -> String {
    let b = s.as_bytes();
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut out = String::new();
    let mut i = 0;
    while i < s.len() {
        if s[i..].starts_with(name)
            && (i == 0 || (!word(b[i - 1]) && b[i - 1] != b'.'))
            && b.get(i + name.len()).is_none_or(|c| !word(*c))
        {
            out.push_str(value);
            i += name.len();
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

/// The rules on `read_repeat.rs`'s text: the key's words and their sources,
/// and the global function's two maps.
fn violations(text: &str) -> Vec<String> {
    let file = ast::production(READ_REPEAT, text);
    let mut out = Vec::new();
    // 1. the key: six u64 words, in order, `#[repr(C)]` (no padding)
    match file.items.iter().find_map(|i| match i {
        syn::Item::Struct(s) if s.ident == "ReadSeenKey" => Some(s),
        _ => None,
    }) {
        None => out.push("no struct ReadSeenKey".to_string()),
        Some(s) => {
            let fields: Vec<(String, String)> = s
                .fields
                .iter()
                .map(|f| {
                    (
                        f.ident.as_ref().map(|i| i.to_string()).unwrap_or_default(),
                        ast::compact(&f.ty),
                    )
                })
                .collect();
            let names: Vec<&str> = fields.iter().map(|(n, _)| n.as_str()).collect();
            if names != KEY {
                out.push(format!("ReadSeenKey's words are {names:?}, not {KEY:?}"));
            }
            for (n, ty) in &fields {
                if ty != "u64" {
                    out.push(format!("ReadSeenKey.{n} is {ty}, not u64"));
                }
            }
            if !s.attrs.iter().any(|a| ast::compact(a) == "#[repr(C)]") {
                out.push("ReadSeenKey is not #[repr(C)]".to_string());
            }
        }
    }
    // 2. what each word is built from, in `repeat`
    match item_fn(&file, "repeat") {
        None => out.push("no fn repeat".to_string()),
        Some(f) => {
            let mut lets = Lets::default();
            lets.visit_item_fn(f);
            let mut lits = KeyLiterals::default();
            lits.visit_item_fn(f);
            if lits.0.len() != 1 {
                out.push(format!(
                    "repeat builds {} ReadSeenKey, not one",
                    lits.0.len()
                ));
            }
            for lit in &lits.0 {
                for (word, from) in KEY_FROM {
                    match lit.iter().find(|(n, _)| n == word) {
                        None => out.push(format!("repeat's key has no {word}")),
                        Some((_, e)) => {
                            let got = resolve(e, &lets.0);
                            if got != from {
                                out.push(format!("repeat's key.{word} is {got}, not {from}"));
                            }
                        }
                    }
                }
            }
        }
    }
    // 3. the global function: the sensor's map for SEEN_OPEN, else FIM's
    match item_fn(&file, "nn_read_repeat") {
        None => out.push("no fn nn_read_repeat".to_string()),
        Some(f) => {
            let body = ast::compact(&f.block);
            let want = "ifwhich==SEEN_OPEN{repeat(&crate::open_sensor::OPEN_READ_SEEN,&key)}else{repeat(&crate::fim_watch::FIM_READ_SEEN,&key)}";
            if !body.contains(want) {
                out.push(format!("nn_read_repeat does not judge in {want}: {body}"));
            }
            let sig = ast::compact(&f.sig);
            if sig != "extern\"C\"fnnn_read_repeat(which:u64,dev:u64,ino:u64)->u64" {
                out.push(format!("nn_read_repeat's signature: {sig}"));
            }
        }
    }
    out
}

/// The calls of `name` (its path's last segment) in a file, as compact tokens.
#[derive(Default)]
struct Calls<'n>(&'n str, Vec<String>);

impl<'ast> Visit<'ast> for Calls<'_> {
    fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = &*c.func {
            if ast::last(&p.path) == self.0 {
                self.1.push(ast::compact(c));
            }
        }
        syn::visit::visit_expr_call(self, c);
    }
}

fn calls(rel: &str, name: &str) -> Vec<String> {
    let file = ast::production(rel, &source(rel));
    let mut c = Calls(name, Vec::new());
    c.visit_file(&file);
    c.1
}

#[test]
fn the_read_repeat_key_carries_the_task_s_image() {
    let v = violations(&source(READ_REPEAT));
    assert!(v.is_empty(), "{v:#?}");
}

/// The sensor's two judgements — the FIM watch's `Opened` and the sensor's
/// record — go through the global function, each on its own map; the plain
/// observer (no task buffer) through `repeat` itself. Nothing else judges a
/// repeat.
#[test]
fn every_repeat_is_judged_by_the_image_keyed_filter() {
    assert_eq!(
        calls(OPEN_SENSOR, "nn_read_repeat"),
        vec![
            "crate::read_repeat::nn_read_repeat(crate::read_repeat::SEEN_FIM,key.dev,key.ino)",
            "crate::read_repeat::nn_read_repeat(crate::read_repeat::SEEN_OPEN,key.dev,key.ino)",
        ]
    );
    assert_eq!(calls(OPEN_SENSOR, "repeat"), Vec::<String>::new());
    assert_eq!(
        calls(FIM_WATCH, "repeat"),
        vec!["crate::read_repeat::repeat(&FIM_READ_SEEN,&key)"]
    );
    // the FIM watch's call site is the watched path's (`SEEN_FIM` first, in
    // `on_open_in`, before the sensor's armed test)
    let os = ast::compact(&ast::production(OPEN_SENSOR, &source(OPEN_SENSOR)));
    let fim = os.find("SEEN_FIM").unwrap();
    let armed = os[fim..].find("if!armed()").map(|i| i + fim);
    let open = os.find("SEEN_OPEN").unwrap();
    assert!(
        armed.is_some_and(|a| a < open),
        "SEEN_FIM, then the armed test, then SEEN_OPEN"
    );
}

/// Each rule fails on a planted violation of the real source.
#[test]
fn a_key_without_the_image_fails_the_ratchet() {
    let real = source(READ_REPEAT);
    let plants: [(&str, &str, &str); 6] = [
        // the image's `mm` dropped from the key
        ("            mm,\n", "", "repeat's key has no mm"),
        // the executable's inode dropped
        (
            "            exe_inode: peek(exe_file + off!(FILE_F_INODE_OFFSET) as u64),\n",
            "",
            "repeat's key has no exe_inode",
        ),
        // the inode read from the wrong place (the `struct file` itself)
        (
            "exe_inode: peek(exe_file + off!(FILE_F_INODE_OFFSET) as u64)",
            "exe_inode: exe_file",
            "repeat's key.exe_inode",
        ),
        // `mm` taken from another task field
        (
            "let mm = peek(task + off!(TASK_STRUCT_MM_OFFSET) as u64);",
            "let mm = peek(task + off!(TASK_STRUCT_START_TIME_OFFSET) as u64);",
            "repeat's key.mm",
        ),
        // the two maps crossed
        (
            "repeat(&crate::open_sensor::OPEN_READ_SEEN, &key)",
            "repeat(&crate::fim_watch::FIM_READ_SEEN, &key)",
            "nn_read_repeat does not judge",
        ),
        // a word that is not a u64
        (
            "    exe_inode: u64,",
            "    exe_inode: u32,",
            "ReadSeenKey.exe_inode is u32",
        ),
    ];
    for (from, to, why) in plants {
        assert!(real.contains(from), "the plant's text is gone: {from:?}");
        let planted = real.replacen(from, to, 1);
        let v = violations(&planted);
        assert!(
            v.iter().any(|m| m.contains(why)),
            "planted {from:?} -> {to:?}: wanted {why:?}, got {v:#?}"
        );
    }
}
