//! Lot 315 (external bug hunt 1.4, family F6; the triage's N2 and BUG-110):
//! in the copy-on-first-write guard a file is its device, its inode number
//! and its birth time — and a ratchet so it stays so.
//!
//! An inode number is given to the next file created once the old one is
//! gone: compared with the device alone, a new file of the owner's that
//! inherited the number of a file the attack deleted was "the attack's
//! renamed copy" and moved into the journal's evidence, then deleted by
//! its expiry (N2, data loss); `pick` merged two files into one entry
//! (BUG-110); a writer's copy of the old file stood for the new one; the
//! new file's write-opens counted as the old one's. `agent/src/cow/
//! identity.rs` holds the only comparisons (`FileId::may_be`, `==`,
//! `FileId::surely_is`) and the only key (`Slot`). One rule holds that:
//!
//! **None, by shape**: the production code of `agent/src/cow/` outside
//! `identity.rs` holds no comparison of an inode number and no list that
//! holds a device and an inode number (a key, a tuple compared, a pattern,
//! a function's parameters, the arguments of a lookup by number) — but
//! `FileId::new(dev, ino, btime)`, which makes the identity.
//!
//! Lot 1.7b (stage S1, item F12): the scan reads the code as Rust
//! (`support::ast`; test items left out). A comparison is any `==`, `!=`,
//! `<`, `<=`, `>`, `>=`, a comparison by method or by path (`.eq(`,
//! `.cmp(`, `PartialEq::eq(…)`) or an `assert_eq!`/`assert_ne!` of which a
//! side holds an inode number — a field, a method or a name `ino`/`st_ino`,
//! or a `let` bound to one; a list is a tuple, an array, a call's
//! arguments, a pattern or a function's parameters holding both numbers in
//! any order and place. Two shapes are new: a map looked up by an inode
//! number alone (`get`, `insert`, `contains_key`, …), and a type that
//! derives equality, order or a hash over a device and an inode number
//! without a birth time (a key of its own). The review of #542 (F6)
//! bypassed the per-line scan before it; the token-stream scan after it
//! (kept in [`lexical`] only to show it) missed each spelling planted in
//! `the_lexical_bypasses_are_caught`.

mod support;

use std::collections::BTreeMap;
use std::path::Path;

use support::ast::{self, Corpus, FnInfo};
use support::repo_root;
use syn::visit::{self, Visit};
use syn::{Expr, Pat};

/// The one file of the guard that compares inode numbers.
const HELPER: &str = "agent/src/cow/identity.rs";

/// The tree scanned.
const TREE: &str = "agent/src/cow";

fn is_ino(t: &str) -> bool {
    t == "ino" || t == "st_ino"
}

fn is_dev(t: &str) -> bool {
    t == "dev" || t == "st_dev"
}

/// Comparisons by method or by path.
const COMPARE: [&str; 8] = ["eq", "ne", "cmp", "partial_cmp", "lt", "le", "gt", "ge"];

/// Assertions that compare.
const ASSERTS: [&str; 4] = [
    "assert_eq",
    "assert_ne",
    "debug_assert_eq",
    "debug_assert_ne",
];

/// A lookup by key.
const LOOKUPS: [&str; 10] = [
    "get",
    "get_mut",
    "insert",
    "remove",
    "contains_key",
    "contains",
    "entry",
    "get_key_value",
    "range",
    "binary_search",
];

/// Whether `e` is `FileId::new(…)` (through the file's imports).
fn makes_the_identity(ix: &ast::Index<'_>, e: &Expr) -> bool {
    match e {
        Expr::Call(c) => match ast::peel(&c.func) {
            Expr::Path(p) => ix
                .full_paths(&ast::segments(&p.path))
                .iter()
                .any(|f| ast::path_ends(f, &["FileId", "new"])),
            _ => false,
        },
        _ => false,
    }
}

/// The numbers an expression holds: `(a device, an inode number)` — a
/// field, a method or a name of either, or a local `let` bound to one
/// (`let i = a.st_ino;`, followed a few deep); what `FileId::new(…)` takes
/// is the identity's.
struct Holds<'s, 'a> {
    ix: &'s ast::Index<'a>,
    f: Option<&'s FnInfo<'a>>,
    depth: u8,
    dev: bool,
    ino: bool,
}

impl<'a> Visit<'a> for Holds<'_, 'a> {
    fn visit_expr(&mut self, e: &'a Expr) {
        if makes_the_identity(self.ix, e) {
            return;
        }
        let mut name = |n: &str| {
            self.dev |= is_dev(n);
            self.ino |= is_ino(n);
        };
        match e {
            Expr::Field(x) => {
                if let syn::Member::Named(n) = &x.member {
                    name(&n.to_string());
                }
            }
            Expr::MethodCall(m) => name(&m.method.to_string()),
            Expr::Path(p) if p.path.segments.len() == 1 => {
                let n = ast::last(&p.path);
                name(&n);
                // a local bound to a number (`let i = a.st_ino;`), a few
                // deep; a name's other bindings in the function (another
                // scope's) are not followed
                if let Some(f) = self.f {
                    if self.depth < 4 {
                        for b in f.bindings.get(&n).into_iter().flatten() {
                            if b.param || !is_number(b.expr) {
                                continue;
                            }
                            let mut inner = Holds {
                                ix: self.ix,
                                f: self.f,
                                depth: self.depth + 1,
                                dev: false,
                                ino: false,
                            };
                            inner.visit_expr(b.expr);
                            self.dev |= inner.dev;
                            self.ino |= inner.ino;
                        }
                    }
                }
            }
            _ => {}
        }
        visit::visit_expr(self, e);
    }
}

/// Whether `e` is a number itself (under parentheses and casts): a field, a
/// method's value or a name.
fn is_number(e: &Expr) -> bool {
    matches!(
        ast::peel(e),
        Expr::Field(_) | Expr::MethodCall(_) | Expr::Path(_)
    )
}

/// `(a device, an inode number)` in `e`.
fn holds<'a>(ix: &ast::Index<'a>, f: Option<&FnInfo<'a>>, e: &'a Expr) -> (bool, bool) {
    let mut h = Holds {
        ix,
        f,
        depth: 0,
        dev: false,
        ino: false,
    };
    h.visit_expr(e);
    (h.dev, h.ino)
}

/// The names a pattern binds that are a device's or an inode number's.
fn pat_holds(p: &Pat) -> (bool, bool) {
    let mut names = Vec::new();
    ast::pat_idents(p, &mut names);
    (
        names.iter().any(|n| is_dev(n)),
        names.iter().any(|n| is_ino(n)),
    )
}

/// The violations of one file's production code, `(line, what)`.
struct Scan<'s, 'a> {
    ix: &'s ast::Index<'a>,
    fns: Vec<&'s FnInfo<'a>>,
    out: Vec<(usize, String)>,
}

impl<'s, 'a> Scan<'s, 'a> {
    fn f(&self) -> Option<&'s FnInfo<'a>> {
        self.fns.last().copied()
    }
    fn holds(&self, e: &'a Expr) -> (bool, bool) {
        holds(self.ix, self.f(), e)
    }
    fn push(&mut self, line: usize, what: &str) {
        self.out.push((line, what.to_string()));
    }
    /// A list of expressions holding both numbers, in any order.
    fn list(&mut self, line: usize, elems: impl Iterator<Item = &'a Expr>) {
        let (mut dev, mut ino) = (false, false);
        for e in elems {
            let (d, i) = self.holds(e);
            dev |= d;
            ino |= i;
        }
        if dev && ino {
            self.push(line, "a (dev, ino) list");
        }
    }
    fn enter(&mut self, name: &syn::Ident) {
        let line = ast::line(name.span());
        let f = self
            .ix
            .fns
            .iter()
            .find(|f| f.line == line && *name == f.name.as_str());
        if let Some(f) = f {
            self.fns.push(f);
        }
    }
    fn sig(&mut self, sig: &syn::Signature) {
        let (mut dev, mut ino) = (false, false);
        for a in &sig.inputs {
            if let syn::FnArg::Typed(t) = a {
                let (d, i) = pat_holds(&t.pat);
                dev |= d;
                ino |= i;
            }
        }
        if dev && ino {
            self.push(ast::line(sig.ident.span()), "a (dev, ino) list");
        }
    }
}

impl<'s, 'a> Visit<'a> for Scan<'s, 'a> {
    fn visit_item_fn(&mut self, f: &'a syn::ItemFn) {
        let before = self.fns.len();
        self.enter(&f.sig.ident);
        self.sig(&f.sig);
        visit::visit_item_fn(self, f);
        self.fns.truncate(before);
    }
    fn visit_impl_item_fn(&mut self, f: &'a syn::ImplItemFn) {
        let before = self.fns.len();
        self.enter(&f.sig.ident);
        self.sig(&f.sig);
        visit::visit_impl_item_fn(self, f);
        self.fns.truncate(before);
    }
    fn visit_item_struct(&mut self, s: &'a syn::ItemStruct) {
        // a type that is a key by number: equality, order or a hash over a
        // device and an inode number, no birth time
        let derives = s.attrs.iter().any(|a| {
            a.path().is_ident("derive")
                && ["PartialEq", "Eq", "Hash", "PartialOrd", "Ord"]
                    .iter()
                    .any(|d| ast::compact(&a.meta).contains(d))
        });
        let names: Vec<String> = s
            .fields
            .iter()
            .filter_map(|f| f.ident.as_ref().map(ToString::to_string))
            .collect();
        let birth = names
            .iter()
            .any(|n| n.contains("btime") || n.contains("birth"));
        if derives && !birth && names.iter().any(|n| is_dev(n)) && names.iter().any(|n| is_ino(n)) {
            self.push(ast::line(s.ident.span()), "a key type by (dev, ino)");
        }
        visit::visit_item_struct(self, s);
    }
    fn visit_expr(&mut self, e: &'a Expr) {
        if makes_the_identity(self.ix, e) {
            // its arguments are the identity's; what is nested deeper is
            // still read
            if let Expr::Call(c) = e {
                for a in &c.args {
                    visit::visit_expr(self, a);
                }
            }
            return;
        }
        match e {
            Expr::Binary(b)
                if matches!(
                    b.op,
                    syn::BinOp::Eq(_)
                        | syn::BinOp::Ne(_)
                        | syn::BinOp::Lt(_)
                        | syn::BinOp::Le(_)
                        | syn::BinOp::Gt(_)
                        | syn::BinOp::Ge(_)
                ) =>
            {
                if self.holds(&b.left).1 || self.holds(&b.right).1 {
                    self.push(
                        ast::line(syn::spanned::Spanned::span(&b.op)),
                        "an inode number compared",
                    );
                }
            }
            Expr::MethodCall(m) => {
                let name = m.method.to_string();
                let line = ast::line(m.method.span());
                if COMPARE.contains(&name.as_str())
                    && (self.holds(&m.receiver).1 || m.args.iter().any(|a| self.holds(a).1))
                {
                    self.push(line, "an inode number compared");
                }
                if LOOKUPS.contains(&name.as_str()) && m.args.iter().any(|a| self.holds(a).1) {
                    self.push(line, "a lookup by an inode number");
                }
                self.list(line, m.args.iter());
            }
            Expr::Call(c) => {
                let line = ast::line(c.paren_token.span.open());
                let name = match ast::peel(&c.func) {
                    Expr::Path(p) => ast::last(&p.path),
                    _ => String::new(),
                };
                let assert = ASSERTS.iter().any(|a| name == format!("{}{a}", ast::MACRO));
                if (COMPARE.contains(&name.as_str()) || assert)
                    && c.args.iter().any(|a| self.holds(a).1)
                {
                    self.push(line, "an inode number compared");
                }
                if !name.starts_with(ast::MACRO) || assert {
                    self.list(line, c.args.iter());
                }
            }
            Expr::Tuple(t) => self.list(ast::line(t.paren_token.span.open()), t.elems.iter()),
            Expr::Array(a) => self.list(ast::line(a.bracket_token.span.open()), a.elems.iter()),
            Expr::Closure(cl) => {
                let (mut dev, mut ino) = (false, false);
                for p in &cl.inputs {
                    let (d, i) = pat_holds(p);
                    dev |= d;
                    ino |= i;
                }
                if dev && ino {
                    self.push(
                        ast::line(syn::spanned::Spanned::span(cl)),
                        "a (dev, ino) list",
                    );
                }
            }
            _ => {}
        }
        visit::visit_expr(self, e);
    }
    fn visit_pat(&mut self, p: &'a Pat) {
        let line = |s: proc_macro2::Span| ast::line(s);
        let elems: Option<(usize, Vec<&Pat>)> = match p {
            Pat::Tuple(t) => Some((line(t.paren_token.span.open()), t.elems.iter().collect())),
            Pat::TupleStruct(t) => {
                Some((line(t.paren_token.span.open()), t.elems.iter().collect()))
            }
            Pat::Slice(s) => Some((line(s.bracket_token.span.open()), s.elems.iter().collect())),
            _ => None,
        };
        if let Some((l, elems)) = elems {
            let (mut dev, mut ino) = (false, false);
            for e in elems {
                let (d, i) = pat_holds(e);
                dev |= d;
                ino |= i;
            }
            if dev && ino {
                self.push(l, "a (dev, ino) list");
            }
        }
        visit::visit_pat(self, p);
    }
}

/// The violations of the production code of each file of `sources`:
/// `(file, line, what)`.
fn violations_of(sources: &BTreeMap<String, String>) -> Vec<(String, usize, String)> {
    let parsed = ast::parse_all(sources, true);
    let c = Corpus::of(sources, &parsed);
    let mut out = Vec::new();
    for (rel, f) in &parsed {
        let mut scan = Scan {
            ix: &c.files[rel],
            fns: Vec::new(),
            out: Vec::new(),
        };
        scan.visit_file(f);
        let mut v = scan.out;
        v.sort();
        v.dedup();
        out.extend(v.into_iter().map(|(l, w)| (rel.clone(), l, w)));
    }
    out
}

/// The violations of `code` (one file's), `(line, what)`.
fn violations(code: &str) -> Vec<(usize, String)> {
    let one: BTreeMap<String, String> = [("planted.rs".to_string(), code.to_string())].into();
    violations_of(&one)
        .into_iter()
        .map(|(_, l, w)| (l, w))
        .collect()
}

#[test]
fn the_guard_compares_inode_numbers_in_one_place() {
    let sources = ast::tree_sources(&repo_root(), TREE);
    assert!(sources.len() >= 10, "{} files under {TREE}", sources.len());
    assert!(sources.contains_key(HELPER), "{HELPER} not found");
    let all = violations_of(&sources);
    // the helper does compare: the scan sees it
    assert!(
        all.iter().any(|(f, _, _)| f == HELPER),
        "{HELPER}: the scan sees nothing"
    );
    let bad: Vec<String> = all
        .iter()
        .filter(|(f, _, _)| f != HELPER)
        .map(|(f, l, w)| format!("{f}:{l}: `{w}`"))
        .collect();
    assert!(
        bad.is_empty(),
        "an inode number compared, or a (dev, ino) key built, outside {HELPER} — ask \
         FileId::may_be, ==, or FileId::surely_is (with the birth time), and key by \
         FileId::slot():\n{}",
        bad.join("\n")
    );
}

#[test]
fn the_rule_fails_on_planted_violations() {
    for planted in [
        // the shapes main had (store.rs:605, :1001, :948; index.rs:212;
        // restore.rs:180; guard.rs:607)
        "fn f() { let ok = (x.file.dev, x.file.ino) == (e.file.dev, e.file.ino); }",
        "fn f() { if st.st_dev == dev && st.st_ino == ino { } }",
        "fn f() { if (st.st_dev, st.st_ino) != (cur.dev, cur.ino) { } }",
        "fn f() { self.by_inode.get(&(dev, ino)); }",
        "fn f() { let key = (e.file.dev, e.file.ino); }",
        "fn f() { let (dev, ino) = (st.st_dev, st.st_ino); }",
        "fn f() { let k = (m.dev(), m.ino()); }",
        "fn f() { if a.ino != b.ino { } }",
        "fn f() { let key = (job.file.dev, job.file.ino, job.writer); }",
        "fn f() { ix.has_entry_for(dev, ino, writer); }",
        // the review of #542 (F6): what a per-line scan missed
        "fn f() {\n    let k = (\n        a.st_dev,\n        a.st_ino,\n    );\n}",
        "fn f() {\n    if (\n        a.dev,\n        a.ino,\n    ) == key\n    {\n    }\n}",
        "fn f() { let k = (b.st_dev, b.st_ino + 0); }",
        "fn f() { if a.st_ino.eq(&b.st_ino) { } }",
        "fn f() { if a.ino.cmp(&b.ino).is_eq() { } }",
        "fn f() { let k = [a.st_dev, a.st_ino]; }",
        "fn f() {\n    let same = a.st_ino\n        == b.st_ino;\n}",
        // the old signatures
        "fn lookup(dev: u64, ino: u64) -> bool { true }",
    ] {
        assert!(!violations(planted).is_empty(), "not seen: {planted}");
    }
    for clean in [
        "fn f() { let id = FileId::new(st.st_dev, st.st_ino, btime(fd, None)); }",
        "fn f() { let id = super::identity::FileId::new(f.dev, f.ino, None); }",
        "fn f() { if a.file.id().may_be(&b.file.id()) { } }",
        "fn f() { let s = FileState { dev: id.dev, ino: id.ino, size: 1 }; }",
        "fn f() { if m.dev() == dev { } }",
        "fn f() {\n    let c = Current {\n        regular: st.st_mode & libc::S_IFMT == libc::S_IFREG,\n        dev: st.st_dev,\n        ino: st.st_ino,\n    };\n}",
        "fn f() { let id = FileId::new(\n    st.st_dev,\n    st.st_ino,\n    None,\n); }",
        // test items are not production code
        "#[cfg(test)]\nmod tests { fn t() { assert!(a.ino == 2); } }",
        // lot 1.7b: the identity made and compared, a state with its birth
        // time, a lookup by the identity's slot
        "fn f() { if FileId::new(a.dev, a.ino, a.btime) == other { } }",
        "#[derive(PartialEq, Eq)]\nstruct FileState { dev: u64, ino: u64, btime_ns: Option<i64> }",
        "fn f() { self.by_slot.get(&FileId::new(st.st_dev, st.st_ino, None).slot()); }",
    ] {
        assert!(
            violations(clean).is_empty(),
            "seen: {clean}: {:?}",
            violations(clean)
        );
    }
    assert!(Path::new(&repo_root().join(HELPER)).exists());
}

/// Lot 1.7b: the spellings the token-stream scan missed, each planted in a
/// copy of a file of the guard (`journal.rs`): the lexical scan sees
/// nothing more, the AST scan one violation more — an assertion of two
/// inode numbers, a comparison by path (`PartialEq::eq`, `u64::eq`), two
/// numbers held by `let`s and compared, the numbers in the other order or
/// apart in a list, a map looked up by an inode number alone, and a key
/// type of its own.
#[test]
fn the_lexical_bypasses_are_caught() {
    let host = "agent/src/cow/journal.rs";
    let text = std::fs::read_to_string(repo_root().join(host)).unwrap();
    let n = |t: &str| {
        let one: BTreeMap<String, String> = [(host.to_string(), t.to_string())].into();
        violations_of(&one).len()
    };
    let (base_lex, base) = (lexical::violations(&text).len(), n(&text));
    for plant in [
        "fn planted(a: &libc::stat, b: &libc::stat) { debug_assert_eq!(a.st_ino, b.st_ino); }",
        "fn planted(a: &libc::stat, b: &libc::stat) -> bool { PartialEq::eq(&a.st_ino, &b.st_ino) }",
        "fn planted(a: &libc::stat, b: &libc::stat) -> bool { u64::eq(&a.st_ino, &b.st_ino) }",
        "fn planted(a: &libc::stat, b: &libc::stat) -> bool {\n    let i = a.st_ino;\n    let j = b.st_ino;\n    i == j\n}",
        "fn planted(a: &libc::stat) -> (u64, u64) { (a.st_ino, a.st_dev) }",
        "fn planted(a: &libc::stat) -> [u64; 3] { [a.st_dev, a.st_size as u64, a.st_ino] }",
        "fn planted(m: &std::collections::HashMap<u64, u32>, a: &libc::stat) -> bool { m.contains_key(&a.st_ino) }",
        "#[derive(Clone, Copy, PartialEq, Eq, Hash)]\nstruct ByNumber {\n    dev: u64,\n    ino: u64,\n}",
    ] {
        let copy = format!("{text}\n{plant}\n");
        assert_eq!(
            lexical::violations(&copy).len(),
            base_lex,
            "the lexical scan saw it: {plant}"
        );
        assert_eq!(n(&copy), base + 1, "{plant}");
    }
}

/// The scan before lot 1.7b (lexical, over each file as one stream of
/// tokens), kept only to show the spellings it missed.
mod lexical {
    use super::support::{production, strip_comments};

    /// The tokens of `code` with their line: identifiers and numbers, the
    /// two-character operators `==`, `!=`, `::`, `=>`, `->`, `&&`, `||`, and
    /// single punctuation. The file is one stream: a statement or a tuple that
    /// rustfmt splits over lines is scanned whole (the review of #542, F6).
    fn tokens(code: &str) -> Vec<(String, usize)> {
        let b: Vec<char> = code.chars().collect();
        let mut out = Vec::new();
        let mut line = 1usize;
        let mut i = 0;
        while i < b.len() {
            let c = b[i];
            if c == '\n' {
                line += 1;
                i += 1;
            } else if c.is_whitespace() {
                i += 1;
            } else if c.is_ascii_alphanumeric() || c == '_' {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == '_') {
                    i += 1;
                }
                out.push((b[start..i].iter().collect(), line));
            } else {
                let two: String = b[i..(i + 2).min(b.len())].iter().collect();
                if ["==", "!=", "::", "=>", "->", "&&", "||"].contains(&two.as_str()) {
                    out.push((two, line));
                    i += 2;
                } else {
                    out.push((c.to_string(), line));
                    i += 1;
                }
            }
        }
        out
    }

    fn is_ino(t: &str) -> bool {
        t == "ino" || t == "st_ino"
    }

    fn is_dev(t: &str) -> bool {
        t == "dev" || t == "st_dev"
    }

    /// A comparison by method: `.eq(`, `.ne(`, `.cmp(`, `.partial_cmp(`, …
    fn compares_by_method(t: &[(String, usize)], k: usize) -> bool {
        k + 2 < t.len()
            && t[k].0 == "."
            && ["eq", "ne", "cmp", "partial_cmp", "lt", "le", "gt", "ge"]
                .contains(&t[k + 1].0.as_str())
            && t[k + 2].0 == "("
    }

    /// The violations of one file's production code: `(line, what)`.
    pub fn violations(code: &str) -> Vec<(usize, String)> {
        let t = tokens(&production(&strip_comments(code)));
        let mut out = Vec::new();
        // 1. a comparison in a piece (between `;`, `{`, `}`, `,`) that holds an
        //    inode number token
        let mut start = 0;
        for k in 0..=t.len() {
            let end = k == t.len() || [";", "{", "}", ","].contains(&t[k].0.as_str());
            if !end {
                continue;
            }
            let piece = &t[start..k];
            let ino = piece.iter().find(|(x, _)| is_ino(x));
            let cmp = piece.iter().any(|(x, _)| x == "==" || x == "!=")
                || (0..piece.len()).any(|j| compares_by_method(piece, j));
            if let (Some((_, line)), true) = (ino, cmp) {
                out.push((*line, "an inode number compared".to_string()));
            }
            start = k + 1;
        }
        // 2. `dev` then `ino` in a parenthesised or bracketed list (a key, a
        //    tuple compared, a pattern, a lookup by number) — but the
        //    constructor `FileId::new(dev, ino, btime)`
        for (k, (open, line)) in t.iter().enumerate() {
            let close = match open.as_str() {
                "(" => ")",
                "[" => "]",
                _ => continue,
            };
            let constructor =
                k >= 3 && t[k - 3].0 == "FileId" && t[k - 2].0 == "::" && t[k - 1].0 == "new";
            if constructor {
                continue;
            }
            let mut depth = 0i32;
            let mut elems: Vec<Vec<&str>> = vec![Vec::new()];
            for (u, _) in &t[k + 1..] {
                match u.as_str() {
                    "(" | "[" | "{" => depth += 1,
                    ")" | "]" | "}" if depth > 0 => depth -= 1,
                    x if x == close && depth == 0 => break,
                    ")" | "]" | "}" => break,
                    "," if depth == 0 => {
                        elems.push(Vec::new());
                        continue;
                    }
                    _ => {}
                }
                elems.last_mut().unwrap().push(u.as_str());
            }
            let has = |e: &Vec<&str>, f: fn(&str) -> bool| e.iter().any(|x| f(x));
            if elems
                .windows(2)
                .any(|w| has(&w[0], is_dev) && has(&w[1], is_ino))
            {
                out.push((*line, "a (dev, ino) list".to_string()));
            }
        }
        out.sort();
        out.dedup();
        out
    }
}
