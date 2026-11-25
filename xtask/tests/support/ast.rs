//! Lot 1.7a (stage S1, item F12): the ratchets read the sources as Rust.
//!
//! The lexical ratchets were bypassed, review after review, by spellings a
//! reader of text cannot see through: a call rustfmt broke over lines, a
//! prefix held in a `const` or a variable, an argument in parentheses, an
//! array iterated, an import under another name, a function passed as a
//! value, a macro's body. This module parses each file with `syn` and
//!
//! - reads the bodies of the macros that hold Rust as Rust ([`parse`]):
//!   `matches!` becomes the `match` it stands for, `vec![…]` an array, and
//!   any other macro whose body is a list of expressions (`format!`,
//!   `assert!`, `write!`, a log macro's arguments, `concat!`) a call of
//!   `__macro__<name>` with those expressions; a macro of a grammar of its
//!   own ([`GRAMMARS`]: tracing's fields, `json!`) is read part by part, a
//!   `macro_rules!` as the Rust of its rules, and any other macro whose
//!   body is not read — `cfg_if!` among them, or one in a type or a
//!   pattern — fails the walker by its name (only the macros that quote
//!   tokens, [`OPAQUE`], are left as they are, their literals still read);
//! - drops what only a test build compiles ([`production`]): an item, a
//!   statement, a field, an arm or a field value under a `cfg` that is false
//!   without `test` (`cfg(test)`, `cfg(all(test, …))`, `cfg(not(not(test)))`
//!   — but not `cfg(any(test, unix))`, which a release builds), and a
//!   `#[test]` function;
//! - indexes what the ratchets ask about ([`Index`]): every call and method
//!   call, every path in an expression's place (a function passed as a
//!   value), every literal (attributes' too, but no doc comment), every
//!   function, each with its item and line and the expressions around it;
//! - tells what a name can stand for ([`Corpus::values`]): a `let`, a
//!   pattern bound from a value (`if let`, a `match` arm), a `for` loop's or
//!   an iterator closure's item, a parameter as the file's call sites pass
//!   it, a `const`/`static` of the file or of the scan, a field as a struct
//!   literal initialises it, a function's returned value.
//!
//! What a value is: a string as the program would hold it, with `{?}` for a
//! part this reader cannot know (a parameter no call site gives, a value
//! computed at run time) and a `format!` template's placeholders filled
//! where their arguments are known.
//!
//! Lot 1.7b (part 2) moves its ratchets onto the same reader.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use proc_macro2::{Span, TokenStream, TokenTree};
use quote::ToTokens;
use syn::parse::{ParseStream, Parser};
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::visit_mut::{self, VisitMut};
use syn::{
    Attribute, Block, Expr, File, FnArg, ImplItem, Item, Lit, Macro, Member, Meta, Pat, Stmt,
    Token, TraitItem,
};

/// The prefix of a macro read as a call: `format!(…)` is
/// `__macro__format(…)`.
pub const MACRO: &str = "__macro__";

/// A part of a value this reader cannot know.
pub const UNKNOWN: &str = "{?}";

// ── parsing ─────────────────────────────────────────────────────────────

/// `text` (the file `rel`) parsed, its macros' bodies read as Rust.
pub fn parse(rel: &str, text: &str) -> File {
    let mut file = syn::parse_file(text).unwrap_or_else(|e| {
        panic!(
            "{rel}:{}: does not parse as Rust: {e}",
            e.span().start().line
        )
    });
    let mut expand = Expand::default();
    expand.visit_file_mut(&mut file);
    let mut left = Unread::default();
    left.visit_file(&file);
    let mut unread = expand.unread;
    let reported: Vec<usize> = unread.iter().map(|(l, _, _)| *l).collect();
    unread.extend(left.0.into_iter().filter(|(l, _, _)| !reported.contains(l)));
    unread.sort();
    unread.dedup();
    assert!(
        unread.is_empty(),
        "{rel}: a macro this reader does not read as Rust — read it in support::ast, or list \
         its name with the reason in GRAMMARS (a body read part by part) or OPAQUE (no code): \
         {:#?}",
        unread
            .iter()
            .map(|(l, name, why)| format!("{rel}:{l} `{name}`: {why}"))
            .collect::<Vec<_>>()
    );
    file
}

/// [`parse`], with what only a test build compiles dropped.
pub fn production(rel: &str, text: &str) -> File {
    let mut file = parse(rel, text);
    StripTests.visit_file_mut(&mut file);
    file
}

/// A span's line (1-based).
pub fn line(span: Span) -> usize {
    span.start().line
}

/// The segments of a path as written (`std::fs::read`: `std`, `fs`, `read`).
pub fn segments(path: &syn::Path) -> Vec<String> {
    path.segments.iter().map(|s| s.ident.to_string()).collect()
}

/// The last segment of a path.
pub fn last(path: &syn::Path) -> String {
    path.segments
        .last()
        .map(|s| s.ident.to_string())
        .unwrap_or_default()
}

/// Whether `path` ends with `tail` (`["fs", "read"]` ends `std::fs::read`).
pub fn path_ends(path: &[String], tail: &[&str]) -> bool {
    path.len() >= tail.len()
        && path[path.len() - tail.len()..]
            .iter()
            .zip(tail)
            .all(|(a, b)| a == b)
}

/// The tokens of `t`, whitespace dropped (`read_state(format!("/proc/{pid}/comm"))`).
pub fn compact<T: ToTokens>(t: &T) -> String {
    t.to_token_stream()
        .to_string()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

/// `e` under its parentheses, groups, `&`, `*`, `?`, `.await` and casts.
pub fn peel(mut e: &Expr) -> &Expr {
    loop {
        e = match e {
            Expr::Paren(p) => &p.expr,
            Expr::Group(g) => &g.expr,
            Expr::Reference(r) => &r.expr,
            Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => &u.expr,
            Expr::Try(t) => &t.expr,
            Expr::Await(a) => &a.base,
            Expr::Cast(c) => &c.expr,
            _ => return e,
        };
    }
}

/// The identifiers a pattern binds.
pub fn pat_idents(pat: &Pat, out: &mut Vec<String>) {
    match pat {
        Pat::Ident(p) => {
            out.push(p.ident.to_string());
            if let Some((_, sub)) = &p.subpat {
                pat_idents(sub, out);
            }
        }
        Pat::Type(p) => pat_idents(&p.pat, out),
        Pat::Tuple(p) => p.elems.iter().for_each(|e| pat_idents(e, out)),
        Pat::TupleStruct(p) => p.elems.iter().for_each(|e| pat_idents(e, out)),
        Pat::Struct(p) => p.fields.iter().for_each(|f| pat_idents(&f.pat, out)),
        Pat::Slice(p) => p.elems.iter().for_each(|e| pat_idents(e, out)),
        Pat::Reference(p) => pat_idents(&p.pat, out),
        Pat::Or(p) => p.cases.iter().for_each(|e| pat_idents(e, out)),
        Pat::Paren(p) => pat_idents(&p.pat, out),
        Pat::Guard(p) => pat_idents(&p.pat, out),
        _ => {}
    }
}

/// The path of a tuple-struct pattern (`Ok(t)`: `Ok`), under `&` and
/// parentheses.
pub fn pat_variant(pat: &Pat) -> Option<String> {
    match pat {
        Pat::TupleStruct(p) => Some(last(&p.path)),
        Pat::Reference(p) => pat_variant(&p.pat),
        Pat::Paren(p) => pat_variant(&p.pat),
        Pat::Guard(p) => pat_variant(&p.pat),
        Pat::Ident(p) => p.subpat.as_ref().and_then(|(_, s)| pat_variant(s)),
        _ => None,
    }
}

// ── macros read as Rust ─────────────────────────────────────────────────

/// Macros whose bodies are no code to read, each with why: they quote
/// tokens or name them. Lot 1.7a (the review of #624): `macro_rules!` is
/// read ([`macro_rules_item`]) and `cfg_if!` fails the walker
/// ([`NOT_READ`]) — neither hides code.
const OPAQUE: &[(&str, &str)] = &[
    ("stringify", "its body is text, never run"),
    ("quote", "tokens a proc macro writes out, never run here"),
    (
        "quote_spanned",
        "tokens a proc macro writes out, never run here",
    ),
    ("parse_quote", "tokens a proc macro parses, never run here"),
    (
        "parse_quote_spanned",
        "tokens a proc macro parses, never run here",
    ),
    ("format_ident", "an identifier made, no code"),
    ("concat_idents", "an identifier made, no code"),
    (
        "include",
        "the file it names is read as a file of its own (the one use: a watchdog test \
         including agent/tests/common/agent_state.rs, a scanned file)",
    ),
];

/// Lot 1.7a (the review of #624): macros whose body is code under
/// conditions this reader does not read — the walker fails on each use.
const NOT_READ: &[(&str, &str)] = &[(
    "cfg_if",
    "its branches are items under `cfg`s this reader does not weigh: write them as \
     `#[cfg]` items",
)];

/// Lot 1.7a (the review of #624): macros whose body is no list of
/// expressions, each with its grammar — read part by part
/// ([`body_exprs`]: every expression it holds, the literals around them).
/// Any other macro whose body does not parse fails the walker.
const GRAMMARS: &[(&str, &str)] = &[
    ("trace", "tracing's fields (`target:`, `k = %v`, `?v`)"),
    ("debug", "tracing's fields (`target:`, `k = %v`, `?v`)"),
    ("info", "tracing's fields (`target:`, `k = %v`, `?v`)"),
    ("warn", "tracing's fields (`target:`, `k = %v`, `?v`)"),
    ("error", "tracing's fields (`target:`, `k = %v`, `?v`)"),
    ("json", "serde_json's object syntax (`{ \"k\": v }`)"),
    ("select", "tokio's arms (`pat = future => body`)"),
    (
        "signed_verbs",
        "agent/src/admin/verify.rs's table of the signed verbs (`Request: Op(Extra), quorum, \
         roles, \"name\";`); its rules are read at its `macro_rules!`",
    ),
    (
        "event_kinds",
        "nn-core's contract table of the event kinds (`Kind => class,`); its rules are read at \
         its `macro_rules!`",
    ),
    (
        "steps",
        "common/src/cgroup_limits.rs's unrolled parse (`p; 0 1 2 …`); its rule is read at its \
         `macro_rules!`",
    ),
];

fn listed(list: &[(&str, &str)], name: &str) -> bool {
    list.iter().any(|(n, _)| *n == name)
}

/// The line of a macro's name.
fn mac_line(mac: &Macro) -> usize {
    line(
        mac.path
            .segments
            .last()
            .map_or_else(Span::call_site, |s| s.ident.span()),
    )
}

/// The body of `mac` read as an expression: `matches!` a `match`, `vec!`
/// an array, any other a call of `__macro__<name>` with the expressions
/// its body holds — a list of expressions, or, for a macro of
/// [`GRAMMARS`], its parts ([`body_exprs`]). `Ok(None)`: an [`OPAQUE`]
/// macro, left as it is (its literals are read). `Err`: why the body is
/// not read.
fn macro_expr(mac: &Macro) -> Result<Option<Expr>, String> {
    let name = last(&mac.path);
    if listed(OPAQUE, &name) {
        return Ok(None);
    }
    if let Some((_, why)) = NOT_READ.iter().find(|(n, _)| *n == name) {
        return Err((*why).to_string());
    }
    let special = |t: syn::Result<TokenStream>| -> Result<Option<Expr>, String> {
        t.and_then(syn::parse2)
            .map(Some)
            .map_err(|e| format!("its body is no `{name}!`: {e}"))
    };
    match name.as_str() {
        "matches" => {
            return special(mac.parse_body_with(|input: ParseStream| {
                let e: Expr = input.parse()?;
                input.parse::<Token![,]>()?;
                let pat = Pat::parse_multi_with_leading_vert(input)?;
                let guard = if input.peek(Token![if]) {
                    input.parse::<Token![if]>()?;
                    Some(input.parse::<Expr>()?)
                } else {
                    None
                };
                let _ = input.parse::<Option<Token![,]>>()?;
                Ok(match guard {
                    Some(g) => quote::quote!(match (#e) { #pat if #g => true, _ => false }),
                    None => quote::quote!(match (#e) { #pat => true, _ => false }),
                })
            }));
        }
        "vec" => {
            return special(
                mac.parse_body_with(|input: ParseStream| {
                    let e: Expr = input.parse()?;
                    input.parse::<Token![;]>()?;
                    let n: Expr = input.parse()?;
                    Ok(quote::quote!([#e; #n]))
                })
                .or_else(|_| {
                    mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated)
                        .map(|elems| quote::quote!([#elems]))
                }),
            );
        }
        _ => {}
    }
    let args: Vec<Expr> = match mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated)
    {
        Ok(p) => p.into_iter().collect(),
        Err(_) if listed(GRAMMARS, &name) => body_exprs(mac.tokens.clone()),
        Err(e) => return Err(format!("its body is no list of expressions: {e}")),
    };
    let span = mac
        .path
        .segments
        .last()
        .map_or_else(Span::call_site, |s| s.ident.span());
    let f = syn::Ident::new(&format!("{MACRO}{name}"), span);
    syn::parse2(quote::quote!(#f(#(#args),*)))
        .map(Some)
        .map_err(|e| format!("its expressions as a call: {e}"))
}

/// Every expression a macro's body holds, whatever its grammar (a log
/// macro's `target: …`, `field = %value`, `?value`; `json!`'s keys and
/// values; `select!`'s arms): the body cut at its own `,`, `;` and `=>`,
/// each part read from its first token that starts an expression, the
/// literals and the groups before it read on their own.
pub fn body_exprs(ts: TokenStream) -> Vec<Expr> {
    let mut out = Vec::new();
    let mut parts: Vec<Vec<TokenTree>> = vec![Vec::new()];
    let toks: Vec<TokenTree> = ts.into_iter().collect();
    let mut i = 0;
    while i < toks.len() {
        let cut = match &toks[i] {
            TokenTree::Punct(p) if p.as_char() == ',' || p.as_char() == ';' => 1,
            TokenTree::Punct(p)
                if p.as_char() == '='
                    && p.spacing() == proc_macro2::Spacing::Joint
                    && matches!(toks.get(i + 1), Some(TokenTree::Punct(q)) if q.as_char() == '>') =>
            {
                2
            }
            _ => 0,
        };
        if cut > 0 {
            parts.push(Vec::new());
            i += cut;
            continue;
        }
        parts.last_mut().unwrap().push(toks[i].clone());
        i += 1;
    }
    for part in parts {
        let mut j = 0;
        while j < part.len() {
            let rest: TokenStream = part[j..].iter().cloned().collect();
            if let Ok(e) = syn::parse2::<Expr>(rest) {
                out.push(e);
                break;
            }
            match &part[j] {
                TokenTree::Literal(l) => out.push(Expr::Lit(syn::ExprLit {
                    attrs: Vec::new(),
                    lit: Lit::new(l.clone()),
                })),
                TokenTree::Group(g) => out.extend(body_exprs(g.stream())),
                _ => {}
            }
            j += 1;
        }
    }
    out
}

/// Reads the macros' bodies as Rust, nested ones too: an expression's or a
/// statement's macro becomes an expression ([`macro_expr`]), an item's
/// (`thread_local!`) the items it declares, or a function
/// `__macro__<name>` of its expressions; a `macro_rules!` a module of its
/// rules ([`macro_rules_item`]). Lot 1.7a (the review of #624): a macro
/// whose body is not read is in `unread` (line, name, why), which fails
/// the walker.
#[derive(Default)]
struct Expand {
    unread: Vec<(usize, String, String)>,
}

impl Expand {
    fn read(&mut self, mac: &Macro) -> Option<Expr> {
        match macro_expr(mac) {
            Ok(e) => e,
            Err(why) => {
                self.unread
                    .push((mac_line(mac), format!("{}!", last(&mac.path)), why));
                None
            }
        }
    }
}

impl VisitMut for Expand {
    fn visit_expr_mut(&mut self, e: &mut Expr) {
        if let Expr::Macro(m) = e {
            if let Some(new) = self.read(&m.mac) {
                *e = new;
            }
        }
        visit_mut::visit_expr_mut(self, e);
    }

    fn visit_stmt_mut(&mut self, s: &mut Stmt) {
        let new = match s {
            Stmt::Macro(m) => self.read(&m.mac).map(|e| {
                let e = match e {
                    Expr::Call(mut c) => {
                        c.attrs = m.attrs.clone();
                        Expr::Call(c)
                    }
                    other => other,
                };
                Stmt::Expr(e, m.semi_token)
            }),
            _ => None,
        };
        if let Some(new) = new {
            *s = new;
        }
        visit_mut::visit_stmt_mut(self, s);
    }

    fn visit_item_mut(&mut self, i: &mut Item) {
        let new = match i {
            Item::Macro(m) if last(&m.mac.path) == "macro_rules" => {
                let name = m
                    .ident
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                match macro_rules_item(&name, &m.attrs, m.mac.tokens.clone()) {
                    Ok(item) => Some(item),
                    Err(why) => {
                        self.unread
                            .push((mac_line(&m.mac), format!("macro_rules! {name}"), why));
                        None
                    }
                }
            }
            Item::Macro(m) if m.ident.is_none() && !listed(OPAQUE, &last(&m.mac.path)) => {
                let mac_name = last(&m.mac.path);
                let name = syn::Ident::new(
                    &format!("{MACRO}{mac_name}"),
                    m.mac
                        .path
                        .segments
                        .last()
                        .map_or_else(Span::call_site, |s| s.ident.span()),
                );
                let attrs = &m.attrs;
                let exprs = m
                    .mac
                    .parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated)
                    .map(|p| p.into_iter().collect::<Vec<_>>());
                let tokens = if let Some((_, why)) = NOT_READ.iter().find(|(n, _)| *n == mac_name) {
                    Err((*why).to_string())
                } else if let Ok(f) = syn::parse2::<File>(m.mac.tokens.clone()) {
                    let items = &f.items;
                    Ok(quote::quote!(#(#attrs)* mod #name { #(#items)* }))
                } else if let Ok(exprs) = exprs {
                    Ok(quote::quote!(#(#attrs)* fn #name() { #(#exprs;)* }))
                } else if listed(GRAMMARS, &mac_name) {
                    let exprs = body_exprs(m.mac.tokens.clone());
                    Ok(quote::quote!(#(#attrs)* fn #name() { #(#exprs;)* }))
                } else {
                    Err("its body is no items and no list of expressions".to_string())
                };
                match tokens.and_then(|t| {
                    syn::parse2::<Item>(t).map_err(|e| format!("its body as an item: {e}"))
                }) {
                    Ok(item) => Some(item),
                    Err(why) => {
                        self.unread
                            .push((mac_line(&m.mac), format!("{mac_name}!"), why));
                        None
                    }
                }
            }
            _ => None,
        };
        if let Some(new) = new {
            *i = new;
        }
        visit_mut::visit_item_mut(self, i);
    }
}

/// Lot 1.7a (the review of #624): the macros left in a file once
/// [`Expand`] read it that are not [`OPAQUE`] — one in a place it does not
/// read (a type's, a pattern's, an impl's item), or one whose body it could
/// not read: each fails the walker.
#[derive(Default)]
struct Unread(Vec<(usize, String, String)>);

impl<'a> Visit<'a> for Unread {
    fn visit_macro(&mut self, m: &'a Macro) {
        let name = last(&m.path);
        if !listed(OPAQUE, &name) {
            self.0.push((
                mac_line(m),
                format!("{name}!"),
                "not read as Rust (a macro in a type, a pattern or an impl's items, or a body \
                 not read)"
                    .to_string(),
            ));
        }
    }
}

/// Lot 1.7a (the review of #624): a `macro_rules!` read as Rust — the
/// module `__macro__rules_<name>` holding, for each rule, the items its
/// transcriber declares or a function `__rule<n>` of its statements, each
/// metavariable (`$x`) a name (`__mv_x`), `$crate` the crate, a repetition
/// (`$(…),*`) its body once. `Err`: a rule whose transcriber is no Rust so
/// read.
fn macro_rules_item(name: &str, attrs: &[Attribute], tokens: TokenStream) -> Result<Item, String> {
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    let mut items: Vec<TokenStream> = Vec::new();
    let (mut i, mut rule) = (0, 0);
    while i < trees.len() {
        let arrow = matches!(
            (trees.get(i + 1), trees.get(i + 2)),
            (Some(TokenTree::Punct(a)), Some(TokenTree::Punct(b)))
                if a.as_char() == '=' && b.as_char() == '>'
        );
        let (TokenTree::Group(_), true, Some(TokenTree::Group(body))) =
            (&trees[i], arrow, trees.get(i + 3))
        else {
            return Err(format!("rule {rule}: no `(matcher) => {{transcriber}}`"));
        };
        let ts = metavariables(body.stream());
        let f = syn::Ident::new(&format!("__rule{rule}"), Span::call_site());
        if let Ok(file) = syn::parse2::<File>(ts.clone()) {
            let its = &file.items;
            items.push(quote::quote!(#(#its)*));
        } else {
            match Block::parse_within.parse2(ts) {
                Ok(stmts) => items.push(quote::quote!(fn #f() { #(#stmts)* })),
                Err(e) => {
                    return Err(format!(
                        "rule {rule}: its transcriber is no items and no statements once its \
                         metavariables are names: {e}"
                    ));
                }
            }
        }
        i += 4;
        if matches!(trees.get(i), Some(TokenTree::Punct(p)) if p.as_char() == ';') {
            i += 1;
        }
        rule += 1;
    }
    let m = syn::Ident::new(&format!("{MACRO}rules_{name}"), Span::call_site());
    syn::parse2::<Item>(quote::quote!(#(#attrs)* mod #m { #(#items)* }))
        .map_err(|e| format!("its rules as a module: {e}"))
}

/// A transcriber's tokens with each metavariable (`$x`) a name (`__mv_x`),
/// `$crate` the crate, and each repetition (`$(…)sep*`) its body once.
fn metavariables(ts: TokenStream) -> TokenStream {
    let trees: Vec<TokenTree> = ts.into_iter().collect();
    let op = |t: Option<&TokenTree>| matches!(t, Some(TokenTree::Punct(q)) if matches!(q.as_char(), '*' | '+' | '?'));
    let mut out: Vec<TokenTree> = Vec::new();
    let mut i = 0;
    while i < trees.len() {
        match (&trees[i], trees.get(i + 1)) {
            (TokenTree::Punct(p), Some(TokenTree::Ident(id))) if p.as_char() == '$' => {
                out.push(TokenTree::Ident(if id == "crate" {
                    id.clone()
                } else {
                    proc_macro2::Ident::new(&format!("__mv_{id}"), id.span())
                }));
                i += 2;
            }
            (TokenTree::Punct(p), Some(TokenTree::Group(g)))
                if p.as_char() == '$' && g.delimiter() == proc_macro2::Delimiter::Parenthesis =>
            {
                out.extend(metavariables(g.stream()));
                i += 2;
                if op(trees.get(i)) {
                    i += 1;
                } else if op(trees.get(i + 1)) {
                    i += 2;
                }
            }
            (TokenTree::Group(g), _) => {
                let mut new = proc_macro2::Group::new(g.delimiter(), metavariables(g.stream()));
                new.set_span(g.span());
                out.push(TokenTree::Group(new));
                i += 1;
            }
            (t, _) => {
                out.push(t.clone());
                i += 1;
            }
        }
    }
    out.into_iter().collect()
}

// ── what only a test build compiles ─────────────────────────────────────

/// A `cfg` predicate's value in a release build: `test` false, the rest
/// unknown.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Cfg {
    Yes,
    No,
    Maybe,
}

/// The features only a test build enables: the test doors (`test-util`)
/// and the agent tests' OCSF validator (`schema-check`) — `supply_chain.rs`
/// (lot 349, `TEST_ONLY_FEATURES`) proves no release carries them. The
/// lab's features (`test-privileged`, `debug-trigger`) run on the lab's
/// guests: their code is scanned.
const TEST_FEATURES: &[&str] = &["test-util", "schema-check"];

fn eval_cfg(meta: &Meta) -> Cfg {
    match meta {
        Meta::Path(p) if p.is_ident("test") => Cfg::No,
        Meta::NameValue(nv)
            if nv.path.is_ident("feature")
                && matches!(&nv.value, Expr::Lit(syn::ExprLit { lit: Lit::Str(v), .. })
                    if TEST_FEATURES.contains(&v.value().as_str())) =>
        {
            Cfg::No
        }
        Meta::Path(_) | Meta::NameValue(_) => Cfg::Maybe,
        Meta::List(l) => {
            let parts: Vec<Cfg> = l
                .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                .map(|p| p.iter().map(eval_cfg).collect())
                .unwrap_or_default();
            if l.path.is_ident("all") {
                if parts.contains(&Cfg::No) {
                    Cfg::No
                } else if parts.iter().all(|c| *c == Cfg::Yes) {
                    Cfg::Yes
                } else {
                    Cfg::Maybe
                }
            } else if l.path.is_ident("any") {
                if parts.contains(&Cfg::Yes) {
                    Cfg::Yes
                } else if parts.iter().all(|c| *c == Cfg::No) {
                    Cfg::No
                } else {
                    Cfg::Maybe
                }
            } else if l.path.is_ident("not") && parts.len() == 1 {
                match parts[0] {
                    Cfg::Yes => Cfg::No,
                    Cfg::No => Cfg::Yes,
                    Cfg::Maybe => Cfg::Maybe,
                }
            } else {
                Cfg::Maybe
            }
        }
    }
}

/// Whether `attrs` keep their item out of a release build: a `cfg` false
/// without `test`, or `#[test]` (`#[tokio::test]`).
pub fn test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| {
        let p = a.path();
        if p.is_ident("cfg") {
            return a
                .parse_args::<Meta>()
                .is_ok_and(|m| eval_cfg(&m) == Cfg::No);
        }
        matches!(&a.meta, Meta::Path(_)) && p.segments.len() <= 2 && last(p) == "test"
    })
}

fn item_attrs(i: &Item) -> &[Attribute] {
    match i {
        Item::Const(x) => &x.attrs,
        Item::Enum(x) => &x.attrs,
        Item::ExternCrate(x) => &x.attrs,
        Item::Fn(x) => &x.attrs,
        Item::ForeignMod(x) => &x.attrs,
        Item::Impl(x) => &x.attrs,
        Item::Macro(x) => &x.attrs,
        Item::Mod(x) => &x.attrs,
        Item::Static(x) => &x.attrs,
        Item::Struct(x) => &x.attrs,
        Item::Trait(x) => &x.attrs,
        Item::TraitAlias(x) => &x.attrs,
        Item::Type(x) => &x.attrs,
        Item::Union(x) => &x.attrs,
        Item::Use(x) => &x.attrs,
        _ => &[],
    }
}

fn impl_item_attrs(i: &ImplItem) -> &[Attribute] {
    match i {
        ImplItem::Const(x) => &x.attrs,
        ImplItem::Fn(x) => &x.attrs,
        ImplItem::Type(x) => &x.attrs,
        ImplItem::Macro(x) => &x.attrs,
        _ => &[],
    }
}

fn trait_item_attrs(i: &TraitItem) -> &[Attribute] {
    match i {
        TraitItem::Const(x) => &x.attrs,
        TraitItem::Fn(x) => &x.attrs,
        TraitItem::Type(x) => &x.attrs,
        TraitItem::Macro(x) => &x.attrs,
        _ => &[],
    }
}

/// The outer attributes of an expression (a statement's).
fn expr_attrs(e: &Expr) -> &[Attribute] {
    macro_rules! attrs {
        ($($v:ident),*) => {
            match e {
                $(Expr::$v(x) => &x.attrs,)*
                _ => &[],
            }
        };
    }
    attrs!(
        Array, Assign, Async, Await, Binary, Block, Break, Call, Cast, Closure, Const, Continue,
        Field, ForLoop, Group, If, Index, Infer, Let, Lit, Loop, Macro, Match, MethodCall, Paren,
        Path, Range, RawAddr, Reference, Repeat, Return, Struct, Try, TryBlock, Tuple, Unary,
        Unsafe, While, Yield
    )
}

fn stmt_test_only(s: &Stmt) -> bool {
    match s {
        Stmt::Local(l) => test_only(&l.attrs),
        Stmt::Item(i) => test_only(item_attrs(i)),
        Stmt::Macro(m) => test_only(&m.attrs),
        Stmt::Expr(e, _) => test_only(expr_attrs(e)),
    }
}

/// Drops what only a test build compiles.
struct StripTests;

impl VisitMut for StripTests {
    fn visit_file_mut(&mut self, f: &mut File) {
        f.items.retain(|i| !test_only(item_attrs(i)));
        visit_mut::visit_file_mut(self, f);
    }
    fn visit_item_mod_mut(&mut self, m: &mut syn::ItemMod) {
        if let Some((_, items)) = &mut m.content {
            items.retain(|i| !test_only(item_attrs(i)));
        }
        visit_mut::visit_item_mod_mut(self, m);
    }
    fn visit_item_impl_mut(&mut self, i: &mut syn::ItemImpl) {
        i.items.retain(|i| !test_only(impl_item_attrs(i)));
        visit_mut::visit_item_impl_mut(self, i);
    }
    fn visit_item_trait_mut(&mut self, t: &mut syn::ItemTrait) {
        t.items.retain(|i| !test_only(trait_item_attrs(i)));
        visit_mut::visit_item_trait_mut(self, t);
    }
    fn visit_block_mut(&mut self, b: &mut Block) {
        b.stmts.retain(|s| !stmt_test_only(s));
        visit_mut::visit_block_mut(self, b);
    }
    fn visit_fields_named_mut(&mut self, f: &mut syn::FieldsNamed) {
        f.named = std::mem::take(&mut f.named)
            .into_iter()
            .filter(|x| !test_only(&x.attrs))
            .collect();
        visit_mut::visit_fields_named_mut(self, f);
    }
    fn visit_fields_unnamed_mut(&mut self, f: &mut syn::FieldsUnnamed) {
        f.unnamed = std::mem::take(&mut f.unnamed)
            .into_iter()
            .filter(|x| !test_only(&x.attrs))
            .collect();
        visit_mut::visit_fields_unnamed_mut(self, f);
    }
    fn visit_item_enum_mut(&mut self, e: &mut syn::ItemEnum) {
        e.variants = std::mem::take(&mut e.variants)
            .into_iter()
            .filter(|x| !test_only(&x.attrs))
            .collect();
        visit_mut::visit_item_enum_mut(self, e);
    }
    fn visit_expr_struct_mut(&mut self, s: &mut syn::ExprStruct) {
        s.fields = std::mem::take(&mut s.fields)
            .into_iter()
            .filter(|x| !test_only(&x.attrs))
            .collect();
        visit_mut::visit_expr_struct_mut(self, s);
    }
    fn visit_expr_match_mut(&mut self, m: &mut syn::ExprMatch) {
        m.arms.retain(|a| !test_only(&a.attrs));
        visit_mut::visit_expr_match_mut(self, m);
    }
}

// ── the files ───────────────────────────────────────────────────────────

/// The production code of every product tree (the file set of
/// `support::product_code`: [`super::product_trees`], files only a test
/// build declares left out), parsed: `(rel, text)`.
pub fn product_sources(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for t in super::product_trees(root) {
        for (rel, text) in tree_sources(root, &t) {
            if super::test_only_file(root, &rel) {
                continue;
            }
            out.insert(rel, text);
        }
    }
    out
}

/// Every `.rs` file under `root/dir`, by repository-relative path.
pub fn tree_sources(root: &Path, dir: &str) -> BTreeMap<String, String> {
    let mut files = Vec::new();
    super::rs_files(&root.join(dir), &mut files);
    files
        .into_iter()
        .map(|f| {
            let rel = f
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(&f).unwrap_or_else(|e| panic!("{rel}: {e}"));
            (rel, text)
        })
        .collect()
}

/// Each source parsed: its production code ([`production`]) when `prod`,
/// all of it otherwise.
pub fn parse_all(sources: &BTreeMap<String, String>, prod: bool) -> BTreeMap<String, File> {
    sources
        .iter()
        .map(|(rel, text)| {
            let f = if prod {
                production(rel, text)
            } else {
                parse(rel, text)
            };
            (rel.clone(), f)
        })
        .collect()
}

// ── the index of a file ─────────────────────────────────────────────────

/// A function of the file (its id: its place in [`Index::fns`]).
pub type FnId = usize;

/// What surrounds a site, innermost last.
#[derive(Clone, Copy)]
pub enum Anc<'a> {
    Expr(&'a Expr),
    Local(&'a syn::Local),
}

/// A name's binding in a function: the expression it stands for, in the
/// scope that expression is in; `each`: an item of it (a `for` loop's, an
/// iterator closure's parameter).
#[derive(Clone, Copy)]
pub struct Binding<'a> {
    pub expr: &'a Expr,
    pub scope: Option<FnId>,
    pub each: bool,
    /// a parameter, bound at a call site of the function
    pub param: bool,
}

/// A function: `fn`, a method, a trait's default body.
pub struct FnInfo<'a> {
    pub name: String,
    /// `module::Type::name`
    pub item: String,
    pub line: usize,
    /// The identifiers each parameter binds, `self` not counted.
    pub params: Vec<Vec<String>>,
    pub has_self: bool,
    /// The type of the `impl` (or the trait) a method is in; `None` for a
    /// free function.
    pub owner: Option<String>,
    pub body: Option<&'a Block>,
    pub bindings: BTreeMap<String, Vec<Binding<'a>>>,
    /// The values it returns: its body's tail and its `return`s.
    pub returns: Vec<&'a Expr>,
}

/// A call: `f(…)` (`path` the callee as written) or `x.f(…)`
/// (`receiver`).
pub struct Call<'a> {
    pub name: String,
    pub path: Option<Vec<String>>,
    pub receiver: Option<&'a Expr>,
    pub args: Vec<&'a Expr>,
    pub expr: &'a Expr,
    pub item: String,
    pub scope: Option<FnId>,
    pub line: usize,
    /// Its byte offset in the file (its `(`'s, a method's name's).
    pub at: usize,
    pub anc: Vec<Anc<'a>>,
}

/// A path in an expression's place (`fs::read`, `FD`, `x`): `called` when
/// it is a call's callee.
pub struct PathRef<'a> {
    pub segs: Vec<String>,
    pub expr: &'a Expr,
    pub called: bool,
    pub item: String,
    pub scope: Option<FnId>,
    pub line: usize,
    /// Its byte offset in the file.
    pub at: usize,
    pub anc: Vec<Anc<'a>>,
}

/// A literal: a string, byte string or C string (its text, bytes made
/// UTF-8 lossily), or the string a `concat!` joins (`joined`).
#[derive(Clone, Debug)]
pub struct LitSite {
    pub value: String,
    pub item: String,
    pub line: usize,
    pub joined: bool,
    /// a `char` literal (`'/'`)
    pub char: bool,
}

/// One file, indexed.
pub struct Index<'a> {
    pub rel: String,
    pub text: &'a str,
    pub fns: Vec<FnInfo<'a>>,
    pub calls: Vec<Call<'a>>,
    pub paths: Vec<PathRef<'a>>,
    pub lits: Vec<LitSite>,
    /// `const`/`static` initialisers by name (associated ones too).
    pub consts: BTreeMap<String, Vec<&'a Expr>>,
    /// A field's initialisers in the file's struct literals, by field name.
    pub fields: BTreeMap<String, Vec<(&'a Expr, Option<FnId>)>>,
    /// `use` items: a local name's full paths.
    pub imports: BTreeMap<String, Vec<Vec<String>>>,
    /// `use …::*` prefixes.
    pub globs: Vec<Vec<String>>,
    /// The macros left unread (their literals are in `lits`).
    pub opaque_macros: Vec<(String, usize)>,
}

impl FnInfo<'_> {
    /// Whether `name` is a local of this function (a parameter, a `let`, a
    /// pattern's or a closure's binding).
    pub fn is_local(&self, name: &str) -> bool {
        self.params.iter().flatten().any(|p| p == name) || self.bindings.contains_key(name)
    }
}

impl<'a> Index<'a> {
    /// `file` (parsed from `text`), indexed.
    pub fn new(rel: &str, text: &'a str, file: &'a File) -> Self {
        let mut ix = Indexer {
            out: Index {
                rel: rel.to_string(),
                text,
                fns: Vec::new(),
                calls: Vec::new(),
                paths: Vec::new(),
                lits: Vec::new(),
                consts: BTreeMap::new(),
                fields: BTreeMap::new(),
                imports: BTreeMap::new(),
                globs: Vec::new(),
                opaque_macros: Vec::new(),
            },
            item: Vec::new(),
            fn_stack: Vec::new(),
            anc: Vec::new(),
        };
        ix.visit_file(file);
        let mut out = ix.out;
        out.bind_parameters();
        out
    }

    /// Each parameter of the file's functions bound to what the file's call
    /// sites of that very function pass: a free function's by its name (or
    /// a module path to it), a method's by `self.f(…)`, `Self::f(…)` or
    /// `Type::f(…)` — never another type's method of the same name.
    fn bind_parameters(&mut self) {
        let mut by_name: BTreeMap<&str, Vec<FnId>> = BTreeMap::new();
        for (id, f) in self.fns.iter().enumerate() {
            by_name.entry(f.name.as_str()).or_default().push(id);
        }
        let mut add: Vec<(FnId, String, Binding<'a>)> = Vec::new();
        for c in &self.calls {
            let Some(ids) = by_name.get(c.name.as_str()) else {
                continue;
            };
            for &id in ids {
                let f = &self.fns[id];
                let calls_it = match (&f.owner, c.receiver, &c.path) {
                    (None, None, Some(p)) => {
                        p.len() == 1
                            || p[p.len() - 2]
                                .chars()
                                .next()
                                .is_some_and(|ch| ch.is_ascii_lowercase())
                    }
                    (Some(_), Some(r), _) => {
                        matches!(peel(r), Expr::Path(x) if x.path.is_ident("self"))
                    }
                    (Some(owner), None, Some(p)) => {
                        p.len() >= 2 && (p[p.len() - 2] == "Self" || p[p.len() - 2] == *owner)
                    }
                    _ => false,
                };
                if !calls_it {
                    continue;
                }
                // `Type::f(x, a)` of a method passes `self` first
                let skip = usize::from(f.has_self && c.receiver.is_none());
                for (i, names) in f.params.iter().enumerate() {
                    let Some(arg) = c.args.get(i + skip) else {
                        continue;
                    };
                    for n in names {
                        add.push((
                            id,
                            n.clone(),
                            Binding {
                                expr: arg,
                                scope: c.scope,
                                each: false,
                                param: true,
                            },
                        ));
                    }
                }
            }
        }
        for (id, n, b) in add {
            self.fns[id].bindings.entry(n).or_default().push(b);
        }
    }

    /// A path's full spellings: its first segment through the file's
    /// imports (`use std::fs as f;` makes `f::read` `std::fs::read`), a
    /// glob import's prefix before a bare name, and itself.
    pub fn full_paths(&self, segs: &[String]) -> Vec<Vec<String>> {
        let mut out = vec![segs.to_vec()];
        if let Some(first) = segs.first() {
            for full in self.imports.get(first).into_iter().flatten() {
                let mut p = full.clone();
                p.extend_from_slice(&segs[1..]);
                out.push(p);
            }
            if segs.len() == 1 {
                for g in &self.globs {
                    let mut p = g.clone();
                    p.push(first.clone());
                    out.push(p);
                }
            }
        }
        out
    }

    /// The source text of a span, comments dropped.
    pub fn source(&self, from: Span, to: Span) -> String {
        let (a, b) = (from.byte_range().start, to.byte_range().end);
        if a >= b || b > self.text.len() {
            return String::new();
        }
        super::strip_comments(&self.text[a..b])
    }

    /// The function `id`'s item path, or the file's top.
    pub fn item_of(&self, scope: Option<FnId>) -> &str {
        scope.map_or("", |id| self.fns[id].item.as_str())
    }
}

struct Indexer<'a> {
    out: Index<'a>,
    item: Vec<String>,
    fn_stack: Vec<FnId>,
    anc: Vec<Anc<'a>>,
}

impl<'a> Indexer<'a> {
    fn item(&self) -> String {
        self.item.join("::")
    }
    fn scope(&self) -> Option<FnId> {
        self.fn_stack.last().copied()
    }
    fn bind(&mut self, pat: &Pat, expr: &'a Expr, each: bool) {
        let Some(id) = self.scope() else {
            return;
        };
        let mut names = Vec::new();
        pat_idents(pat, &mut names);
        for n in names {
            self.out.fns[id]
                .bindings
                .entry(n)
                .or_default()
                .push(Binding {
                    expr,
                    scope: Some(id),
                    each,
                    param: false,
                });
        }
    }
    fn lit(&mut self, lit: &Lit) {
        let (value, char) = match lit {
            Lit::Str(s) => (s.value(), false),
            Lit::ByteStr(s) => (String::from_utf8_lossy(&s.value()).into_owned(), false),
            Lit::CStr(s) => (
                String::from_utf8_lossy(s.value().to_bytes()).into_owned(),
                false,
            ),
            Lit::Char(c) => (c.value().to_string(), true),
            _ => return,
        };
        let line = line(lit.span());
        let item = self.item();
        self.out.lits.push(LitSite {
            value,
            item,
            line,
            joined: false,
            char,
        });
    }
    /// The literals of tokens no parser read (an opaque macro, an
    /// attribute), `concat!`'s joins among them.
    fn token_lits(&mut self, tokens: TokenStream) {
        let trees: Vec<TokenTree> = tokens.into_iter().collect();
        for (i, t) in trees.iter().enumerate() {
            match t {
                TokenTree::Literal(l) => self.lit(&Lit::new(l.clone())),
                TokenTree::Group(g) => {
                    let is_concat = i >= 2
                        && matches!(&trees[i - 1], TokenTree::Punct(p) if p.as_char() == '!')
                        && matches!(&trees[i - 2], TokenTree::Ident(id) if id == "concat");
                    if is_concat {
                        if let Ok(args) = Parser::parse2(
                            Punctuated::<Expr, Token![,]>::parse_terminated,
                            g.stream(),
                        ) {
                            let joined: String = args.iter().map(literal_text).collect();
                            let line = line(g.span());
                            let item = self.item();
                            self.out.lits.push(LitSite {
                                value: joined,
                                item,
                                line,
                                joined: true,
                                char: false,
                            });
                        }
                    }
                    self.token_lits(g.stream());
                }
                _ => {}
            }
        }
    }
    fn enter_fn(
        &mut self,
        name: String,
        line: usize,
        sig: &'a syn::Signature,
        body: Option<&'a Block>,
        owner: Option<String>,
    ) {
        let mut params = Vec::new();
        let mut has_self = false;
        for a in &sig.inputs {
            match a {
                FnArg::Receiver(_) => has_self = true,
                FnArg::Typed(t) => {
                    let mut n = Vec::new();
                    pat_idents(&t.pat, &mut n);
                    params.push(n);
                }
            }
        }
        let mut returns = Vec::new();
        if let Some(b) = body {
            if let Some(Stmt::Expr(e, None)) = b.stmts.last() {
                returns.push(e);
            }
            let mut r = Returns(&mut returns);
            r.visit_block(b);
        }
        self.item.push(name.clone());
        let item = self.item();
        self.out.fns.push(FnInfo {
            name,
            item,
            line,
            params,
            has_self,
            owner,
            body,
            bindings: BTreeMap::new(),
            returns,
        });
        self.fn_stack.push(self.out.fns.len() - 1);
    }
    fn leave_fn(&mut self) {
        self.fn_stack.pop();
        self.item.pop();
    }
}

/// The `return`s of a body (not of the closures and functions in it).
struct Returns<'r, 'a>(&'r mut Vec<&'a Expr>);

impl<'a> Visit<'a> for Returns<'_, 'a> {
    fn visit_expr_return(&mut self, r: &'a syn::ExprReturn) {
        if let Some(e) = &r.expr {
            self.0.push(e);
        }
        visit::visit_expr_return(self, r);
    }
    fn visit_expr_closure(&mut self, _: &'a syn::ExprClosure) {}
    fn visit_item_fn(&mut self, _: &'a syn::ItemFn) {}
}

/// A literal argument's text (`concat!`'s parts).
fn literal_text(e: &Expr) -> String {
    match e {
        Expr::Lit(l) => match &l.lit {
            Lit::Str(s) => s.value(),
            Lit::ByteStr(s) => String::from_utf8_lossy(&s.value()).into_owned(),
            Lit::Char(c) => c.value().to_string(),
            Lit::Int(i) => i.base10_digits().to_string(),
            Lit::Bool(b) => b.value.to_string(),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

fn use_tree(prefix: &mut Vec<String>, tree: &syn::UseTree, ix: &mut Index<'_>) {
    match tree {
        syn::UseTree::Path(p) => {
            prefix.push(p.ident.to_string());
            use_tree(prefix, &p.tree, ix);
            prefix.pop();
        }
        syn::UseTree::Name(n) => {
            let name = n.ident.to_string();
            if name == "self" {
                if let Some(local) = prefix.last().cloned() {
                    ix.imports.entry(local).or_default().push(prefix.clone());
                }
            } else {
                let mut full = prefix.clone();
                full.push(name.clone());
                ix.imports.entry(name).or_default().push(full);
            }
        }
        syn::UseTree::Rename(r) => {
            let mut full = prefix.clone();
            if r.ident != "self" {
                full.push(r.ident.to_string());
            }
            ix.imports
                .entry(r.rename.to_string())
                .or_default()
                .push(full);
        }
        syn::UseTree::Glob(_) => ix.globs.push(prefix.clone()),
        syn::UseTree::Group(g) => {
            for t in &g.items {
                use_tree(prefix, t, ix);
            }
        }
    }
}

fn type_name(t: &syn::Type) -> String {
    match t {
        syn::Type::Path(p) => last(&p.path),
        syn::Type::Reference(r) => type_name(&r.elem),
        _ => "_".to_string(),
    }
}

impl<'a> Visit<'a> for Indexer<'a> {
    fn visit_attribute(&mut self, a: &'a Attribute) {
        // a doc comment is prose; another attribute's literals are read
        if !a.path().is_ident("doc") {
            self.token_lits(a.meta.to_token_stream());
        }
    }

    fn visit_item_fn(&mut self, f: &'a syn::ItemFn) {
        self.enter_fn(
            f.sig.ident.to_string(),
            line(f.sig.ident.span()),
            &f.sig,
            Some(&*f.block),
            None,
        );
        visit::visit_item_fn(self, f);
        self.leave_fn();
    }

    fn visit_impl_item_fn(&mut self, f: &'a syn::ImplItemFn) {
        self.enter_fn(
            f.sig.ident.to_string(),
            line(f.sig.ident.span()),
            &f.sig,
            Some(&f.block),
            self.item.last().cloned(),
        );
        visit::visit_impl_item_fn(self, f);
        self.leave_fn();
    }

    fn visit_trait_item_fn(&mut self, f: &'a syn::TraitItemFn) {
        self.enter_fn(
            f.sig.ident.to_string(),
            line(f.sig.ident.span()),
            &f.sig,
            f.default.as_ref(),
            self.item.last().cloned(),
        );
        visit::visit_trait_item_fn(self, f);
        self.leave_fn();
    }

    fn visit_item_impl(&mut self, i: &'a syn::ItemImpl) {
        self.item.push(type_name(&i.self_ty));
        visit::visit_item_impl(self, i);
        self.item.pop();
    }

    fn visit_item_trait(&mut self, t: &'a syn::ItemTrait) {
        self.item.push(t.ident.to_string());
        visit::visit_item_trait(self, t);
        self.item.pop();
    }

    fn visit_item_mod(&mut self, m: &'a syn::ItemMod) {
        self.item.push(m.ident.to_string());
        visit::visit_item_mod(self, m);
        self.item.pop();
    }

    fn visit_item_const(&mut self, c: &'a syn::ItemConst) {
        self.out
            .consts
            .entry(c.ident.to_string())
            .or_default()
            .push(&c.expr);
        self.item.push(c.ident.to_string());
        visit::visit_item_const(self, c);
        self.item.pop();
    }

    fn visit_item_static(&mut self, s: &'a syn::ItemStatic) {
        self.out
            .consts
            .entry(s.ident.to_string())
            .or_default()
            .push(&s.expr);
        self.item.push(s.ident.to_string());
        visit::visit_item_static(self, s);
        self.item.pop();
    }

    fn visit_impl_item_const(&mut self, c: &'a syn::ImplItemConst) {
        self.out
            .consts
            .entry(c.ident.to_string())
            .or_default()
            .push(&c.expr);
        self.item.push(c.ident.to_string());
        visit::visit_impl_item_const(self, c);
        self.item.pop();
    }

    fn visit_trait_item_const(&mut self, c: &'a syn::TraitItemConst) {
        if let Some((_, e)) = &c.default {
            self.out
                .consts
                .entry(c.ident.to_string())
                .or_default()
                .push(e);
        }
        visit::visit_trait_item_const(self, c);
    }

    fn visit_item_use(&mut self, u: &'a syn::ItemUse) {
        let mut prefix = Vec::new();
        use_tree(&mut prefix, &u.tree, &mut self.out);
    }

    fn visit_local(&mut self, l: &'a syn::Local) {
        if let Some(init) = &l.init {
            self.bind(&l.pat, &init.expr, false);
        }
        self.anc.push(Anc::Local(l));
        visit::visit_local(self, l);
        self.anc.pop();
    }

    fn visit_macro(&mut self, m: &'a Macro) {
        // a macro no parser read: its literals still count
        self.out.opaque_macros.push((
            last(&m.path),
            line(
                m.path
                    .segments
                    .last()
                    .map_or_else(Span::call_site, |s| s.ident.span()),
            ),
        ));
        self.token_lits(m.tokens.clone());
    }

    fn visit_lit(&mut self, l: &'a Lit) {
        self.lit(l);
    }

    fn visit_expr(&mut self, e: &'a Expr) {
        let line_of = |s: Span| line(s);
        match e {
            Expr::Call(c) => {
                let callee = peel(&c.func);
                let path = match callee {
                    Expr::Path(p) => Some(segments(&p.path)),
                    _ => None,
                };
                let name = path
                    .as_ref()
                    .and_then(|p| p.last().cloned())
                    .unwrap_or_default();
                if path
                    .as_ref()
                    .is_some_and(|p| p.len() == 1 && p[0] == format!("{MACRO}concat"))
                {
                    let joined: String = c.args.iter().map(literal_text).collect();
                    let item = self.item();
                    self.out.lits.push(LitSite {
                        value: joined,
                        item,
                        line: line_of(c.paren_token.span.open()),
                        joined: true,
                        char: false,
                    });
                }
                let call = Call {
                    name,
                    path,
                    receiver: None,
                    args: c.args.iter().collect(),
                    expr: e,
                    item: self.item(),
                    scope: self.scope(),
                    line: line_of(c.paren_token.span.open()),
                    at: c.paren_token.span.open().byte_range().start,
                    anc: self.anc.clone(),
                };
                self.out.calls.push(call);
            }
            Expr::MethodCall(m) => {
                // an iterator closure's parameter is an item of the receiver
                for a in &m.args {
                    if let Expr::Closure(cl) = peel(a) {
                        for p in &cl.inputs {
                            self.bind(p, &m.receiver, true);
                        }
                    }
                }
                let call = Call {
                    name: m.method.to_string(),
                    path: None,
                    receiver: Some(&m.receiver),
                    args: m.args.iter().collect(),
                    expr: e,
                    item: self.item(),
                    scope: self.scope(),
                    line: line_of(m.method.span()),
                    at: m.method.span().byte_range().start,
                    anc: self.anc.clone(),
                };
                self.out.calls.push(call);
            }
            // an assignment's target (`x = …`, a log macro's `field = …`)
            // names no function
            Expr::Path(_) if matches!(self.anc.last(), Some(Anc::Expr(Expr::Assign(a))) if std::ptr::eq(&*a.left, e)) =>
                {}
            Expr::Path(p) => {
                let called = matches!(self.anc.last(), Some(Anc::Expr(Expr::Call(c))) if std::ptr::eq(peel(&c.func), e));
                let first = p
                    .path
                    .segments
                    .first()
                    .map_or_else(Span::call_site, |s| s.ident.span());
                let r = PathRef {
                    segs: segments(&p.path),
                    expr: e,
                    called,
                    item: self.item(),
                    scope: self.scope(),
                    line: line_of(first),
                    at: first.byte_range().start,
                    anc: self.anc.clone(),
                };
                self.out.paths.push(r);
            }
            Expr::ForLoop(f) => self.bind(&f.pat, &f.expr, true),
            Expr::Let(l) => self.bind(&l.pat, &l.expr, false),
            Expr::Match(m) => {
                for a in &m.arms {
                    self.bind(&a.pat, &m.expr, false);
                }
            }
            Expr::Struct(s) => {
                let scope = self.scope();
                for f in &s.fields {
                    if let Member::Named(n) = &f.member {
                        self.out
                            .fields
                            .entry(n.to_string())
                            .or_default()
                            .push((&f.expr, scope));
                    }
                }
            }
            _ => {}
        }
        self.anc.push(Anc::Expr(e));
        visit::visit_expr(self, e);
        self.anc.pop();
    }
}

// ── what a name stands for ──────────────────────────────────────────────

/// The files of a scan, indexed, and the `const`s and `static`s of all of
/// them by name (a value named from another module).
pub struct Corpus<'a> {
    pub files: BTreeMap<String, Index<'a>>,
    globals: BTreeMap<String, Vec<(String, &'a Expr)>>,
    /// What an expression's values (`false`) or items (`true`) were found
    /// to be: each is worked out once.
    memo: Memo,
}

/// What an expression's values (`false`) or items (`true`) were found to
/// be, by its address and scope.
type Memo = std::cell::RefCell<std::collections::HashMap<(usize, Option<FnId>, bool), Vec<String>>>;

/// The expressions being worked out (a name met again on its own chain).
type Seen = BTreeSet<(usize, Option<FnId>)>;

/// What a name stands for: `(file, expression, scope, an item of it)`.
type Resolved<'a> = Vec<(String, &'a Expr, Option<FnId>, bool)>;

/// At most this many values of one expression.
const MAX_VALUES: usize = 64;
/// At most this deep a chain of names.
const MAX_DEPTH: u8 = 48;

/// Methods whose value is their receiver's (a conversion, a view, an
/// unwrap).
const SAME: &[&str] = &[
    "to_string",
    "to_owned",
    "into",
    "as_str",
    "as_ref",
    "as_path",
    "as_os_str",
    "as_bytes",
    "as_deref",
    "as_c_str",
    "to_path_buf",
    "into_os_string",
    "into_boxed_path",
    "to_str",
    "to_string_lossy",
    "into_owned",
    "clone",
    "borrow",
    "display",
    "unwrap",
    "expect",
    "unwrap_or_default",
    "as_mut",
    "ok",
];

/// Iterator adaptors that keep their receiver's items.
const SAME_ITEMS: &[&str] = &[
    "iter",
    "into_iter",
    "copied",
    "cloned",
    "filter",
    "rev",
    "skip",
    "take",
    "skip_while",
    "take_while",
    "peekable",
    "by_ref",
    "inspect",
    "step_by",
    "fuse",
    "first",
    "last",
    "get",
    "find",
    "next",
    "next_back",
    "nth",
    "min",
    "max",
];

/// Calls whose value is their first argument's (a constructor of a path or
/// a string, a wrapper).
const SAME_ARG: &[&str] = &[
    "from",
    "new",
    "from_str",
    "from_static",
    "from_bytes",
    "from_bytes_with_nul",
    "from_bytes_with_nul_unchecked",
    "from_vec",
    "Some",
    "Ok",
    "Borrowed",
    "Owned",
    // a file opened at a path (`File::open(p)`, `kernel_roots::open(p, f)`)
    "open",
    "create",
    "open_crossing",
];

impl<'a> Corpus<'a> {
    /// `files` (rel → (text, parsed)), indexed.
    pub fn new(files: impl IntoIterator<Item = (&'a str, &'a str, &'a File)>) -> Self {
        let mut out = Corpus {
            files: BTreeMap::new(),
            globals: BTreeMap::new(),
            memo: Default::default(),
        };
        for (rel, text, file) in files {
            let ix = Index::new(rel, text, file);
            for (name, exprs) in &ix.consts {
                for e in exprs {
                    out.globals
                        .entry(name.clone())
                        .or_default()
                        .push((rel.to_string(), e));
                }
            }
            out.files.insert(rel.to_string(), ix);
        }
        out
    }

    /// The corpus of `sources` parsed into `parsed`.
    pub fn of(sources: &'a BTreeMap<String, String>, parsed: &'a BTreeMap<String, File>) -> Self {
        Self::new(
            parsed
                .iter()
                .map(|(rel, f)| (rel.as_str(), sources[rel].as_str(), f)),
        )
    }

    /// The values `e` (in function `scope` of file `rel`) can have.
    pub fn values(&self, rel: &str, e: &'a Expr, scope: Option<FnId>) -> Vec<String> {
        let mut seen = BTreeSet::new();
        let mut v = self.values_in(rel, e, scope, 0, &mut seen);
        v.sort();
        v.dedup();
        v
    }

    /// The values of the items of `e` (an array, a slice, an iterator over
    /// one), or of `e` itself.
    pub fn elements(&self, rel: &str, e: &'a Expr, scope: Option<FnId>) -> Vec<String> {
        let mut seen = BTreeSet::new();
        let mut v = self.elements_in(rel, e, scope, 0, &mut seen);
        v.sort();
        v.dedup();
        v
    }

    /// Every literal under `e`, and under what its names stand for.
    pub fn atoms(&self, rel: &str, e: &'a Expr, scope: Option<FnId>) -> Vec<String> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        self.atoms_in(rel, e, scope, 0, &mut seen, &mut out);
        out.sort();
        out.dedup();
        out
    }

    /// Every call under `e` and under what its names stand for: `(name,
    /// path as written)`.
    pub fn calls_under(&self, rel: &str, e: &'a Expr, scope: Option<FnId>) -> Vec<String> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        self.calls_in(rel, e, scope, 0, &mut seen, &mut out);
        out.sort();
        out.dedup();
        out
    }

    /// What the local name `name` is bound to in function `scope` of
    /// `rel` (a `let`, a pattern, a loop's or a closure's item, a
    /// parameter at the file's call sites).
    pub fn bound(&self, rel: &str, scope: Option<FnId>, name: &str) -> Vec<Binding<'a>> {
        self.bindings(rel, scope, name)
    }

    fn bindings(&self, rel: &str, scope: Option<FnId>, name: &str) -> Vec<Binding<'a>> {
        let Some(ix) = self.files.get(rel) else {
            return Vec::new();
        };
        scope
            .and_then(|id| ix.fns[id].bindings.get(name))
            .cloned()
            .unwrap_or_default()
    }

    /// The `const`/`static` initialisers a path names: the file's by its
    /// last segment, else the scan's.
    fn consts(&self, rel: &str, segs: &[String]) -> Vec<(String, &'a Expr)> {
        let Some(name) = segs.last() else {
            return Vec::new();
        };
        if let Some(local) = self.files.get(rel).and_then(|ix| ix.consts.get(name)) {
            return local.iter().map(|e| (rel.to_string(), *e)).collect();
        }
        self.globals.get(name).cloned().unwrap_or_default()
    }

    /// What the name `segs` stands for: `(file, expression, scope, each)`.
    fn resolve(&self, rel: &str, segs: &[String], scope: Option<FnId>) -> Resolved<'a> {
        let mut out = Vec::new();
        if segs.len() == 1 {
            for b in self.bindings(rel, scope, &segs[0]) {
                out.push((rel.to_string(), b.expr, b.scope, b.each));
            }
            if !out.is_empty() {
                return out;
            }
        }
        if segs.len() == 1 || segs.iter().all(|s| s != "self") {
            for (f, e) in self.consts(rel, segs) {
                out.push((f, e, None, false));
            }
        }
        out
    }

    fn values_in(
        &self,
        rel: &str,
        e: &'a Expr,
        scope: Option<FnId>,
        depth: u8,
        seen: &mut Seen,
    ) -> Vec<String> {
        if depth > MAX_DEPTH {
            return Vec::new();
        }
        self.memoized(rel, e, scope, depth, seen, false)
    }

    /// `values_in` (`items` false) or `elements_in`, each worked out once;
    /// a name met again on its own chain stands for nothing more.
    fn memoized(
        &self,
        rel: &str,
        e: &'a Expr,
        scope: Option<FnId>,
        depth: u8,
        seen: &mut Seen,
        items: bool,
    ) -> Vec<String> {
        let key = (e as *const Expr as usize, scope, items);
        if let Some(v) = self.memo.borrow().get(&key) {
            return v.clone();
        }
        let guard = (e as *const Expr as usize * 2 + usize::from(items), scope);
        if !seen.insert(guard) {
            return Vec::new();
        }
        let mut out = if items {
            self.element_step(rel, e, scope, depth + 1, seen)
        } else {
            self.value_step(rel, e, scope, depth + 1, seen)
        };
        seen.remove(&guard);
        out.sort();
        out.dedup();
        out.truncate(MAX_VALUES);
        self.memo.borrow_mut().insert(key, out.clone());
        out
    }

    fn value_step(
        &self,
        rel: &str,
        e: &'a Expr,
        scope: Option<FnId>,
        d: u8,
        seen: &mut Seen,
    ) -> Vec<String> {
        match e {
            Expr::Lit(l) => match &l.lit {
                Lit::Str(_) | Lit::ByteStr(_) | Lit::CStr(_) | Lit::Char(_) => {
                    vec![literal_value(&l.lit)]
                }
                _ => Vec::new(),
            },
            Expr::Paren(_)
            | Expr::Group(_)
            | Expr::Reference(_)
            | Expr::Try(_)
            | Expr::Await(_)
            | Expr::Cast(_) => self.values_in(rel, peel(e), scope, d, seen),
            Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => {
                self.values_in(rel, &u.expr, scope, d, seen)
            }
            Expr::Block(b) => self.block_values(rel, &b.block, scope, d, seen),
            Expr::Unsafe(b) => self.block_values(rel, &b.block, scope, d, seen),
            Expr::If(i) => {
                let mut v = self.block_values(rel, &i.then_branch, scope, d, seen);
                if let Some((_, el)) = &i.else_branch {
                    v.extend(self.values_in(rel, el, scope, d, seen));
                }
                v
            }
            Expr::Match(m) => m
                .arms
                .iter()
                .flat_map(|a| self.values_in(rel, &a.body, scope, d, seen))
                .collect(),
            Expr::Array(a) => a
                .elems
                .iter()
                .flat_map(|x| self.values_in(rel, x, scope, d, seen))
                .collect(),
            Expr::Tuple(t) => t
                .elems
                .iter()
                .flat_map(|x| self.values_in(rel, x, scope, d, seen))
                .collect(),
            Expr::Repeat(r) => self.values_in(rel, &r.expr, scope, d, seen),
            Expr::Index(i) => self.elements_in(rel, &i.expr, scope, d, seen),
            Expr::Binary(b) if matches!(b.op, syn::BinOp::Add(_)) => {
                let l = self.values_in(rel, &b.left, scope, d, seen);
                let r = self.values_in(rel, &b.right, scope, d, seen);
                product(&or_unknown(l), &or_unknown(r), "")
            }
            Expr::Path(p) => {
                let segs = segments(&p.path);
                let mut v = Vec::new();
                for (f, x, s, each) in self.resolve(rel, &segs, scope) {
                    if each {
                        v.extend(self.elements_in(&f, x, s, d, seen));
                    } else {
                        v.extend(self.values_in(&f, x, s, d, seen));
                    }
                }
                v
            }
            Expr::Field(f) => self.field_values(rel, &f.member, d, seen),
            Expr::MethodCall(m) => {
                let name = m.method.to_string();
                if SAME.contains(&name.as_str()) || SAME_ITEMS.contains(&name.as_str()) {
                    self.values_in(rel, &m.receiver, scope, d, seen)
                } else if name == "join" && m.args.len() == 1 {
                    let r = or_unknown(self.values_in(rel, &m.receiver, scope, d, seen));
                    let a = or_unknown(self.values_in(rel, &m.args[0], scope, d, seen));
                    let mut v = Vec::new();
                    for x in &r {
                        for y in &a {
                            v.push(if y.starts_with('/') {
                                y.clone()
                            } else {
                                format!("{}/{y}", x.trim_end_matches('/'))
                            });
                        }
                    }
                    v
                } else if name == "concat" {
                    // `["/pr", "oc"].concat()`
                    match peel(&m.receiver) {
                        Expr::Array(a) => {
                            let parts: Vec<Vec<String>> = a
                                .elems
                                .iter()
                                .map(|x| or_unknown(self.values_in(rel, x, scope, d, seen)))
                                .collect();
                            parts
                                .iter()
                                .fold(vec![String::new()], |acc, p| product(&acc, p, ""))
                        }
                        _ => Vec::new(),
                    }
                } else {
                    Vec::new()
                }
            }
            Expr::Call(c) => {
                let Expr::Path(p) = peel(&c.func) else {
                    return Vec::new();
                };
                let segs = segments(&p.path);
                let name = segs.last().cloned().unwrap_or_default();
                if name == format!("{MACRO}concat") {
                    let parts: Vec<Vec<String>> = c
                        .args
                        .iter()
                        .map(|x| or_unknown(self.values_in(rel, x, scope, d, seen)))
                        .collect();
                    parts
                        .iter()
                        .fold(vec![String::new()], |acc, p| product(&acc, p, ""))
                } else if name == format!("{MACRO}format") || name == format!("{MACRO}format_args")
                {
                    self.format_values(rel, &c.args, scope, d, seen)
                } else if SAME_ARG.contains(&name.as_str()) && !c.args.is_empty() {
                    self.values_in(rel, &c.args[0], scope, d, seen)
                } else if ["openat", "openat2", "open_beneath"].contains(&name.as_str())
                    && c.args.len() >= 2
                {
                    // a path beneath a directory: `openat(dir, "self/mountinfo", …)`
                    self.values_in(rel, &c.args[1], scope, d, seen)
                } else {
                    // a function of the file: what it returns
                    let mut v = Vec::new();
                    if let Some(ix) = self.files.get(rel) {
                        for (id, f) in ix.fns.iter().enumerate() {
                            if f.name == name {
                                for r in &f.returns {
                                    v.extend(self.values_in(rel, r, Some(id), d, seen));
                                }
                            }
                        }
                    }
                    v
                }
            }
            _ => Vec::new(),
        }
    }

    fn block_values(
        &self,
        rel: &str,
        b: &'a Block,
        scope: Option<FnId>,
        d: u8,
        seen: &mut Seen,
    ) -> Vec<String> {
        match b.stmts.last() {
            Some(Stmt::Expr(e, None)) => self.values_in(rel, e, scope, d, seen),
            _ => Vec::new(),
        }
    }

    fn field_values(&self, rel: &str, member: &Member, d: u8, seen: &mut Seen) -> Vec<String> {
        let Member::Named(n) = member else {
            return Vec::new();
        };
        let Some(ix) = self.files.get(rel) else {
            return Vec::new();
        };
        let inits = ix.fields.get(&n.to_string()).cloned().unwrap_or_default();
        inits
            .into_iter()
            .flat_map(|(x, s)| self.values_in(rel, x, s, d, seen))
            .collect()
    }

    /// A `format!`'s strings: its template with each placeholder filled by
    /// its argument's values (by position, by name, inline), `{?}` where
    /// none is known.
    fn format_values(
        &self,
        rel: &str,
        args: &'a Punctuated<Expr, Token![,]>,
        scope: Option<FnId>,
        d: u8,
        seen: &mut Seen,
    ) -> Vec<String> {
        let Some(Expr::Lit(syn::ExprLit {
            lit: Lit::Str(t), ..
        })) = args.first()
        else {
            return Vec::new();
        };
        let template = t.value();
        let rest: Vec<&'a Expr> = args.iter().skip(1).collect();
        let mut positional = Vec::new();
        let mut named: BTreeMap<String, &'a Expr> = BTreeMap::new();
        for a in rest {
            match a {
                Expr::Assign(x) => {
                    if let Expr::Path(p) = &*x.left {
                        named.insert(last(&p.path), &x.right);
                    }
                }
                _ => positional.push(a),
            }
        }
        let mut out = vec![String::new()];
        let mut next = 0;
        let mut chars = template.chars().peekable();
        let mut lit = String::new();
        while let Some(c) = chars.next() {
            if c == '{' && chars.peek() == Some(&'{') {
                chars.next();
                lit.push('{');
                continue;
            }
            if c == '}' && chars.peek() == Some(&'}') {
                chars.next();
                lit.push('}');
                continue;
            }
            if c != '{' {
                lit.push(c);
                continue;
            }
            let mut spec = String::new();
            for x in chars.by_ref() {
                if x == '}' {
                    break;
                }
                spec.push(x);
            }
            let arg = spec.split(':').next().unwrap_or("").trim().to_string();
            let vals = if arg.is_empty() {
                let v = positional
                    .get(next)
                    .map(|x| self.values_in(rel, x, scope, d, seen));
                next += 1;
                v
            } else if let Ok(i) = arg.parse::<usize>() {
                positional
                    .get(i)
                    .map(|x| self.values_in(rel, x, scope, d, seen))
            } else if let Some(x) = named.get(&arg) {
                Some(self.values_in(rel, x, scope, d, seen))
            } else {
                // inline: `{pid}`
                let segs = vec![arg.clone()];
                let mut v = Vec::new();
                for (f, x, s, each) in self.resolve(rel, &segs, scope) {
                    if each {
                        v.extend(self.elements_in(&f, x, s, d, seen));
                    } else {
                        v.extend(self.values_in(&f, x, s, d, seen));
                    }
                }
                Some(v)
            };
            let vals = or_unknown(vals.unwrap_or_default());
            out = product(&out, &[std::mem::take(&mut lit)], "");
            out = product(&out, &vals, "");
        }
        product(&out, &[lit], "")
    }

    fn elements_in(
        &self,
        rel: &str,
        e: &'a Expr,
        scope: Option<FnId>,
        depth: u8,
        seen: &mut Seen,
    ) -> Vec<String> {
        if depth > MAX_DEPTH {
            return Vec::new();
        }
        self.memoized(rel, e, scope, depth, seen, true)
    }

    fn element_step(
        &self,
        rel: &str,
        e: &'a Expr,
        scope: Option<FnId>,
        d: u8,
        seen: &mut Seen,
    ) -> Vec<String> {
        match peel(e) {
            Expr::Array(a) => a
                .elems
                .iter()
                .flat_map(|x| self.values_in(rel, x, scope, d, seen))
                .collect(),
            Expr::Repeat(r) => self.values_in(rel, &r.expr, scope, d, seen),
            Expr::MethodCall(m)
                if SAME_ITEMS.contains(&m.method.to_string().as_str())
                    || SAME.contains(&m.method.to_string().as_str()) =>
            {
                self.elements_in(rel, &m.receiver, scope, d, seen)
            }
            Expr::MethodCall(m) if m.method == "chain" && m.args.len() == 1 => {
                let mut v = self.elements_in(rel, &m.receiver, scope, d, seen);
                v.extend(self.elements_in(rel, &m.args[0], scope, d, seen));
                v
            }
            Expr::Path(p) => {
                let segs = segments(&p.path);
                let mut v = Vec::new();
                for (f, x, s, _) in self.resolve(rel, &segs, scope) {
                    v.extend(self.elements_in(&f, x, s, d, seen));
                }
                v
            }
            other => self.values_in(rel, other, scope, d, seen),
        }
    }

    fn atoms_in(
        &self,
        rel: &str,
        e: &'a Expr,
        scope: Option<FnId>,
        depth: u8,
        seen: &mut Seen,
        out: &mut Vec<String>,
    ) {
        if depth > MAX_DEPTH {
            return;
        }
        let key = (e as *const Expr as usize, scope);
        if !seen.insert(key) {
            return;
        }
        let mut c = Collect::default();
        c.visit_expr(e);
        out.extend(c.lits);
        for segs in c.paths {
            for (f, x, s, _) in self.resolve(rel, &segs, scope) {
                self.atoms_in(&f, x, s, depth + 1, seen, out);
            }
        }
        for m in c.fields {
            let inits = self
                .files
                .get(rel)
                .and_then(|ix| ix.fields.get(&m))
                .cloned()
                .unwrap_or_default();
            for (x, s) in inits {
                self.atoms_in(rel, x, s, depth + 1, seen, out);
            }
        }
        for name in c.called {
            if let Some(ix) = self.files.get(rel) {
                for (id, f) in ix.fns.iter().enumerate() {
                    if f.name == name {
                        for r in &f.returns {
                            self.atoms_in(rel, r, Some(id), depth + 1, seen, out);
                        }
                    }
                }
            }
        }
    }

    fn calls_in(
        &self,
        rel: &str,
        e: &'a Expr,
        scope: Option<FnId>,
        depth: u8,
        seen: &mut Seen,
        out: &mut Vec<String>,
    ) {
        if depth > MAX_DEPTH {
            return;
        }
        let key = (e as *const Expr as usize, scope);
        if !seen.insert(key) {
            return;
        }
        let mut c = Collect::default();
        c.visit_expr(e);
        out.extend(c.call_names);
        for segs in c.paths {
            if segs.len() != 1 {
                continue;
            }
            // a parameter is not followed to its callers (what reads the
            // value there is the caller's)
            if self.bindings(rel, scope, &segs[0]).iter().any(|b| b.param) {
                continue;
            }
            for (f, x, s, _) in self.resolve(rel, &segs, scope) {
                self.calls_in(&f, x, s, depth + 1, seen, out);
            }
        }
    }
}

/// A literal's value.
fn literal_value(l: &Lit) -> String {
    match l {
        Lit::Str(s) => s.value(),
        Lit::ByteStr(s) => String::from_utf8_lossy(&s.value()).into_owned(),
        Lit::CStr(s) => String::from_utf8_lossy(s.value().to_bytes()).into_owned(),
        Lit::Char(c) => c.value().to_string(),
        _ => String::new(),
    }
}

fn or_unknown(v: Vec<String>) -> Vec<String> {
    if v.is_empty() {
        vec![UNKNOWN.to_string()]
    } else {
        v
    }
}

fn product(a: &[String], b: &[String], sep: &str) -> Vec<String> {
    let mut out = Vec::new();
    for x in a {
        for y in b {
            if out.len() >= MAX_VALUES {
                return out;
            }
            out.push(format!("{x}{sep}{y}"));
        }
    }
    out
}

/// What an expression holds: its literals, the names it uses, the fields
/// it reads, the functions it calls.
#[derive(Default)]
struct Collect {
    lits: Vec<String>,
    paths: Vec<Vec<String>>,
    fields: Vec<String>,
    called: Vec<String>,
    /// every call's name and, for a path call, its path (`File::open`)
    call_names: Vec<String>,
}

impl<'a> Visit<'a> for Collect {
    fn visit_lit(&mut self, l: &'a Lit) {
        let v = literal_value(l);
        if !v.is_empty() {
            self.lits.push(v);
        }
    }
    fn visit_macro(&mut self, m: &'a Macro) {
        fn walk(t: TokenStream, out: &mut Vec<String>) {
            for tt in t {
                match tt {
                    TokenTree::Literal(l) => {
                        let v = literal_value(&Lit::new(l));
                        if !v.is_empty() {
                            out.push(v);
                        }
                    }
                    TokenTree::Group(g) => walk(g.stream(), out),
                    _ => {}
                }
            }
        }
        walk(m.tokens.clone(), &mut self.lits);
    }
    fn visit_expr_path(&mut self, p: &'a syn::ExprPath) {
        self.paths.push(segments(&p.path));
        visit::visit_expr_path(self, p);
    }
    fn visit_expr_field(&mut self, f: &'a syn::ExprField) {
        if let Member::Named(n) = &f.member {
            self.fields.push(n.to_string());
        }
        visit::visit_expr_field(self, f);
    }
    fn visit_expr_call(&mut self, c: &'a syn::ExprCall) {
        if let Expr::Path(p) = peel(&c.func) {
            let segs = segments(&p.path);
            self.called.push(segs.last().cloned().unwrap_or_default());
            self.call_names.push(segs.join("::"));
        }
        visit::visit_expr_call(self, c);
    }
    fn visit_expr_method_call(&mut self, m: &'a syn::ExprMethodCall) {
        self.call_names.push(format!(".{}", m.method));
        visit::visit_expr_method_call(self, m);
    }
}

/// The spine of `e` in its ancestors `anc` (innermost last): the
/// expressions it is the receiver or the operand of, through `?`,
/// parentheses, `&`, `*`, `.await`, casts and fields — `(top, method calls
/// on it in order, the ancestor above the top)`.
pub fn spine<'a>(
    e: &'a Expr,
    anc: &[Anc<'a>],
) -> (&'a Expr, Vec<&'a syn::ExprMethodCall>, Option<Anc<'a>>) {
    let mut cur = e;
    let mut methods = Vec::new();
    for a in anc.iter().rev() {
        let Anc::Expr(p) = a else {
            return (cur, methods, Some(*a));
        };
        let up = match p {
            Expr::MethodCall(m) if std::ptr::eq(&*m.receiver, cur) => {
                methods.push(m);
                true
            }
            Expr::Paren(x) => std::ptr::eq(&*x.expr, cur),
            Expr::Group(x) => std::ptr::eq(&*x.expr, cur),
            Expr::Try(x) => std::ptr::eq(&*x.expr, cur),
            Expr::Reference(x) => std::ptr::eq(&*x.expr, cur),
            Expr::Unary(x) => std::ptr::eq(&*x.expr, cur),
            Expr::Await(x) => std::ptr::eq(&*x.base, cur),
            Expr::Cast(x) => std::ptr::eq(&*x.expr, cur),
            Expr::Field(x) => std::ptr::eq(&*x.base, cur),
            _ => false,
        };
        if !up {
            return (cur, methods, Some(*a));
        }
        cur = p;
    }
    (cur, methods, None)
}
