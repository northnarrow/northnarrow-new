//! Tappa 6.9.7 P3 — deterministic BM25 index over the canonical KB.
//!
//! Builds an on-disk `tantivy` index from the P2 canonical JSONL dumps
//! (MITRE ATT&CK v18.1 + SigmaHQ Linux) **plus** the 6.7 in-repo
//! curated notes (`kb_seed`), under the R3 **security-token-preserving
//! analyzer** so identifiers an English tokenizer would shred
//! (`T1059.001`, `/etc/shadow`, `CVE-2024-1234`, `cmd.exe`,
//! `192.168.1.1`, `v18.1`, long hex) survive as single terms.
//!
//! Charter: `tantivy` is pinned `=0.25.0` with `default-features=false`
//! (the default `columnar-zstd-compression` pulls `zstd-sys` C-FFI —
//! forbidden); the pure-Rust `mmap` + `lz4-compression` set is used.
//!
//! P3 owns the schema, the analyzer, build/open/persist + rebuild-on
//! -source-change, and golden retrieval fixtures. Wiring this behind
//! `RagEngine::retrieve` / a canary flag is P4/P5 — NOT here.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use tantivy::collector::TopDocs;
use tantivy::query::{BooleanQuery, Occur, Query, TermQuery};
use tantivy::schema::{
    Field, IndexRecordOption, Schema, TextFieldIndexing, TextOptions, Value, STORED, STRING,
};
use tantivy::tokenizer::{LowerCaser, TextAnalyzer, Token, TokenStream, Tokenizer};
use tantivy::{Index, TantivyDocument, Term};

use common::rag_types::KbDocument;

/// Registered name of the R3 analyzer (persisted in the schema; must be
/// re-registered on every open — tantivy stores the name, not the impl).
pub const SEC_ANALYZER: &str = "nn_sec";

/// Marker file (next to the index) holding the source fingerprint, so
/// the index is rebuilt iff the ingested corpus changed.
const FINGERPRINT_FILE: &str = ".nn_kb_source_sha256";

// ── R3 security-token-preserving tokenizer ─────────────────────────────

/// A char that may appear *inside* a token. Crucially includes
/// `. / - _ :` so dotted/slashed/hyphenated security identifiers stay
/// whole; everything else (whitespace, `,;()[]{}"'`…) splits.
fn is_token_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '.' | '/' | '-' | '_' | ':')
}

/// Punctuation legitimately *inside* identifiers but also used as
/// sentence punctuation — trimmed only from the trailing edge so
/// `"/etc/shadow."` → `/etc/shadow`, `"T1059.001,"` → `T1059.001`,
/// while internal dots/slashes are preserved.
fn trim_token(raw: &str) -> &str {
    let lead: &[char] = &['(', '[', '{', '"', '\''];
    let trail: &[char] = &['.', ',', ';', ':', '!', '?', ')', ']', '}', '"', '\''];
    raw.trim_start_matches(lead).trim_end_matches(trail)
}

/// Split `text` into security-aware raw tokens (pre-lowercasing).
fn split_tokens(text: &str) -> Vec<Token> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // advance over non-token bytes
        let ch_start = i;
        let c = text[i..].chars().next().unwrap();
        let clen = c.len_utf8();
        if !is_token_char(c) {
            i += clen;
            continue;
        }
        // accumulate a maximal token-char run
        let mut j = ch_start;
        while j < bytes.len() {
            let cj = text[j..].chars().next().unwrap();
            if !is_token_char(cj) {
                break;
            }
            j += cj.len_utf8();
        }
        let raw = &text[ch_start..j];
        let tok = trim_token(raw);
        if !tok.is_empty() {
            out.push(Token {
                offset_from: ch_start,
                offset_to: j,
                position: pos,
                text: tok.to_string(),
                position_length: 1,
            });
            pos += 1;
        }
        i = j;
    }
    out
}

#[derive(Clone, Default)]
pub struct SecurityTokenizer;

pub struct SecTokenStream {
    tokens: Vec<Token>,
    cursor: usize,
}

impl TokenStream for SecTokenStream {
    fn advance(&mut self) -> bool {
        self.cursor += 1;
        self.cursor <= self.tokens.len()
    }
    fn token(&self) -> &Token {
        &self.tokens[self.cursor - 1]
    }
    fn token_mut(&mut self) -> &mut Token {
        &mut self.tokens[self.cursor - 1]
    }
}

impl Tokenizer for SecurityTokenizer {
    type TokenStream<'a> = SecTokenStream;
    fn token_stream<'a>(&'a mut self, text: &'a str) -> SecTokenStream {
        SecTokenStream {
            tokens: split_tokens(text),
            cursor: 0,
        }
    }
}

fn analyzer() -> TextAnalyzer {
    TextAnalyzer::builder(SecurityTokenizer)
        .filter(LowerCaser)
        .build()
}

/// Run the R3 analyzer over `text` and collect the term strings (the
/// exact tokens that go into / are matched against the index).
pub fn analyze(text: &str) -> Vec<String> {
    let mut a = analyzer();
    let mut ts = a.token_stream(text);
    let mut out = Vec::new();
    while ts.advance() {
        out.push(ts.token().text.clone());
    }
    out
}

// ── canonical record (P2 §4.1 8-key) + schema ──────────────────────────

/// The P2 8-key canonical line (parsed from the JSONL dumps). `author`
/// is `Vec<String>` or `null`.
#[derive(Debug, Clone)]
pub struct CanonLine {
    pub author: Option<Vec<String>>,
    pub category: String,
    pub content: String,
    pub id: String,
    pub platform: String,
    pub severity: String,
    pub source_ref: String,
    pub title: String,
}

impl CanonLine {
    /// Parse one canonical JSONL line via `serde_json::Value` (agent
    /// has no `serde` derive dep — avoided a Cargo.toml dep change).
    fn from_json(line: &str) -> Result<Self> {
        let v: serde_json::Value =
            serde_json::from_str(line).context("parse canonical JSONL line")?;
        let s = |k: &str| -> Result<String> {
            v.get(k)
                .and_then(|x| x.as_str())
                .map(str::to_string)
                .ok_or_else(|| anyhow!("missing/!string field {k:?}"))
        };
        let author = match v.get("author") {
            Some(serde_json::Value::Array(a)) => Some(
                a.iter()
                    .filter_map(|e| e.as_str().map(str::to_string))
                    .collect(),
            ),
            _ => None, // null / absent
        };
        Ok(Self {
            author,
            category: s("category")?,
            content: s("content")?,
            id: s("id")?,
            platform: s("platform")?,
            severity: s("severity")?,
            source_ref: s("source_ref")?,
            title: s("title")?,
        })
    }
    /// Map a 6.7 in-repo curated note into the canonical shape (author
    /// `null` — covered wholesale by the repo license; `tags` folded
    /// into `content` for retrievability).
    fn from_kb(d: &KbDocument) -> Self {
        let mut content = d.content.clone();
        if !d.tags.is_empty() {
            content.push_str(&format!("\nTags: {}", d.tags.join(", ")));
        }
        Self {
            author: None,
            category: d.category.as_str().to_string(),
            content,
            id: d.id.clone(),
            platform: String::new(),
            severity: String::new(),
            source_ref: d.id.clone(),
            title: d.title.clone(),
        }
    }
}

/// The 8 schema fields, in canonical order.
#[derive(Clone, Copy)]
pub struct KbFields {
    pub author: Field,
    pub category: Field,
    pub content: Field,
    pub id: Field,
    pub platform: Field,
    pub severity: Field,
    pub source_ref: Field,
    pub title: Field,
}

/// Build the schema. `title`/`content`/`author` are analysed with the
/// R3 [`SEC_ANALYZER`] (free-text BM25); `id`/`category`/`source_ref`/
/// `severity`/`platform` are `STRING` (raw, exact-match, stored).
pub fn build_schema() -> (Schema, KbFields) {
    let sec = TextOptions::default()
        .set_indexing_options(
            TextFieldIndexing::default()
                .set_tokenizer(SEC_ANALYZER)
                .set_index_option(IndexRecordOption::WithFreqsAndPositions),
        )
        .set_stored();
    let mut b = Schema::builder();
    let fields = KbFields {
        author: b.add_text_field("author", sec.clone()),
        category: b.add_text_field("category", STRING | STORED),
        content: b.add_text_field("content", sec.clone()),
        id: b.add_text_field("id", STRING | STORED),
        platform: b.add_text_field("platform", STRING | STORED),
        severity: b.add_text_field("severity", STRING | STORED),
        source_ref: b.add_text_field("source_ref", STRING | STORED),
        title: b.add_text_field("title", sec),
    };
    (b.build(), fields)
}

// ── source loading + fingerprint ───────────────────────────────────────

/// Load all `*.jsonl` canonical dumps in `jsonl_dir` (P2 output) plus
/// the 6.7 in-repo notes, into one record set.
pub fn load_records(jsonl_dir: &Path, seed: &[KbDocument]) -> Result<Vec<CanonLine>> {
    let mut out: Vec<CanonLine> = seed.iter().map(CanonLine::from_kb).collect();
    if jsonl_dir.is_dir() {
        let mut files: Vec<_> = std::fs::read_dir(jsonl_dir)
            .with_context(|| format!("read_dir {}", jsonl_dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
            .collect();
        files.sort();
        for f in files {
            let text = std::fs::read_to_string(&f)
                .with_context(|| format!("read {}", f.display()))?;
            for (n, line) in text.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let rec = CanonLine::from_json(line)
                    .with_context(|| format!("{}:{}", f.display(), n + 1))?;
                out.push(rec);
            }
        }
    }
    Ok(out)
}

/// Deterministic fingerprint over the *ingested corpus* (dedup by id,
/// sorted) — drives rebuild-on-change. Independent of tantivy's
/// (non-deterministic) segment bytes.
pub fn source_fingerprint(records: &[CanonLine]) -> String {
    let mut ids: Vec<&CanonLine> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut sorted: Vec<&CanonLine> = records.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    for r in sorted {
        if seen.insert(r.id.as_str()) {
            ids.push(r);
        }
    }
    let mut h = Sha256::new();
    h.update(b"NN-RAG-KB-INDEX-SRC-v1\0");
    h.update((ids.len() as u32).to_be_bytes());
    for r in ids {
        for s in [
            r.author.as_ref().map(|v| v.join("\u{1}")).unwrap_or_default(),
            r.category.clone(),
            r.content.clone(),
            r.id.clone(),
            r.platform.clone(),
            r.severity.clone(),
            r.source_ref.clone(),
            r.title.clone(),
        ] {
            h.update((s.len() as u32).to_be_bytes());
            h.update(s.as_bytes());
        }
    }
    let d = h.finalize();
    let mut s = String::with_capacity(64);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ── build / open / persist / rebuild-on-change ─────────────────────────

fn index_doc(f: &KbFields, r: &CanonLine) -> TantivyDocument {
    let mut d = TantivyDocument::new();
    if let Some(a) = &r.author {
        d.add_text(f.author, a.join(", "));
    } else {
        d.add_text(f.author, "");
    }
    d.add_text(f.category, &r.category);
    d.add_text(f.content, &r.content);
    d.add_text(f.id, &r.id);
    d.add_text(f.platform, &r.platform);
    d.add_text(f.severity, &r.severity);
    d.add_text(f.source_ref, &r.source_ref);
    d.add_text(f.title, &r.title);
    d
}

/// (Re)build the index in `dir` from `records` (dir is wiped first).
pub fn build_index(records: &[CanonLine], dir: &Path) -> Result<()> {
    if dir.exists() {
        std::fs::remove_dir_all(dir).with_context(|| format!("rm -rf {}", dir.display()))?;
    }
    std::fs::create_dir_all(dir).with_context(|| format!("mkdir -p {}", dir.display()))?;
    let (schema, f) = build_schema();
    let index = Index::create_in_dir(dir, schema).context("create tantivy index")?;
    index.tokenizers().register(SEC_ANALYZER, analyzer());
    let mut writer = index.writer(50_000_000).context("tantivy writer")?;
    let mut seen = BTreeSet::new();
    let mut sorted: Vec<&CanonLine> = records.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    for r in sorted {
        if !seen.insert(r.id.clone()) {
            continue; // dedup by id, deterministic post-sort
        }
        writer
            .add_document(index_doc(&f, r))
            .context("add_document")?;
    }
    writer.commit().context("commit")?;
    std::fs::write(dir.join(FINGERPRINT_FILE), source_fingerprint(records))
        .with_context(|| "write fingerprint marker")?;
    Ok(())
}

/// Open the index in `dir`, rebuilding iff it is absent or the source
/// fingerprint changed (lazy-load + rebuild-on-source-change). The R3
/// analyzer is re-registered on every open (tantivy persists only the
/// name).
pub fn open_or_build(records: &[CanonLine], dir: &Path) -> Result<Index> {
    let fp_now = source_fingerprint(records);
    let fp_old = std::fs::read_to_string(dir.join(FINGERPRINT_FILE)).ok();
    let fresh = fp_old.as_deref() == Some(fp_now.as_str())
        && dir.join("meta.json").is_file();
    if !fresh {
        build_index(records, dir)?;
    }
    let index = Index::open_in_dir(dir).context("open tantivy index")?;
    index.tokenizers().register(SEC_ANALYZER, analyzer());
    Ok(index)
}

// ── BM25 retrieval (P3 golden harness; P4 wraps it in RagEngine) ───────

/// BM25 top-`k` over `title`/`content`/`author`. The query is analysed
/// with the SAME R3 analyzer (no `QueryParser` syntax pitfalls with
/// `/ : .`), then OR-combined as per-field `TermQuery`s — tantivy's
/// default similarity is BM25, so `TopDocs` is BM25-ranked. Returns
/// `(score, id)` best-first.
pub fn bm25_search(index: &Index, query: &str, k: usize) -> Result<Vec<(f32, String)>> {
    let schema = index.schema();
    let id_f = schema.get_field("id").unwrap();
    let title_f = schema.get_field("title").unwrap();
    let content_f = schema.get_field("content").unwrap();
    let author_f = schema.get_field("author").unwrap();

    let terms = analyze(query);
    if terms.is_empty() {
        return Ok(Vec::new());
    }
    let mut clauses: Vec<(Occur, Box<dyn Query>)> = Vec::new();
    for t in &terms {
        for fld in [content_f, title_f, author_f] {
            clauses.push((
                Occur::Should,
                Box::new(TermQuery::new(
                    Term::from_field_text(fld, t),
                    IndexRecordOption::WithFreqs,
                )),
            ));
        }
    }
    let query = BooleanQuery::new(clauses);
    let reader = index.reader().context("index reader")?;
    let searcher = reader.searcher();
    let hits = searcher
        .search(&query, &TopDocs::with_limit(k))
        .context("search")?;
    let mut out = Vec::with_capacity(hits.len());
    for (score, addr) in hits {
        let doc: TantivyDocument = searcher.doc(addr).context("fetch doc")?;
        let id = doc
            .get_first(id_f)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        out.push((score, id));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, title: &str, content: &str, author: Option<Vec<String>>) -> CanonLine {
        CanonLine {
            author,
            category: "test".into(),
            content: content.into(),
            id: id.into(),
            platform: "linux".into(),
            severity: "high".into(),
            source_ref: id.into(),
            title: title.into(),
        }
    }

    #[test]
    fn r3_analyzer_preserves_security_tokens() {
        // The owner's audit-checklist identifiers must survive whole
        // (lowercased — consistent on index + query side).
        let toks = analyze(
            "Detects T1059.001 powershell reading /etc/shadow via cmd.exe \
             from 192.168.1.1 exploiting CVE-2024-1234 hash \
             deadbeefdeadbeef1234 xmrig miner. End.",
        );
        for want in [
            "t1059.001",
            "/etc/shadow",
            "cmd.exe",
            "192.168.1.1",
            "cve-2024-1234",
            "deadbeefdeadbeef1234",
            "xmrig",
        ] {
            assert!(toks.iter().any(|t| t == want), "missing token {want:?} in {toks:?}");
        }
        // Integrity: the technique id must NOT be fragmented.
        assert!(!toks.iter().any(|t| t == "t1059"), "T1059.001 was split");
        // Trailing sentence punctuation trimmed.
        assert!(toks.iter().any(|t| t == "end"));
    }

    fn corpus() -> Vec<CanonLine> {
        vec![
            rec(
                "attack:T1059.001",
                "PowerShell",
                "Adversaries may abuse PowerShell T1059.001 for execution.",
                None,
            ),
            rec(
                "sigma:shadow-1",
                "Sensitive File Access",
                "Detects access to /etc/shadow on linux hosts.",
                Some(vec!["Florian Roth".into()]),
            ),
            rec(
                "attack:T1496",
                "Resource Hijacking",
                "Cryptomining like xmrig consumes resources.",
                None,
            ),
            rec(
                "sigma:certutil-1",
                "Certutil Download",
                "Defense evasion: certutil download of remote payload.",
                Some(vec!["Nasreddine Bencherchali".into()]),
            ),
            rec(
                "attack:T1055",
                "Process Injection",
                "Process injection T1055 evades defenses.",
                None,
            ),
        ]
    }

    #[test]
    fn golden_retrieval_previews() {
        let dir = tempfile::tempdir().unwrap();
        let idx = open_or_build(&corpus(), dir.path()).unwrap();
        let top = |q: &str| -> Vec<String> {
            bm25_search(&idx, q, 5).unwrap().into_iter().map(|(_, id)| id).collect()
        };
        assert!(top("T1059.001 powershell").contains(&"attack:T1059.001".to_string()));
        assert!(top("/etc/shadow").contains(&"sigma:shadow-1".to_string()));
        assert!(top("xmrig").contains(&"attack:T1496".to_string()));
        assert!(top("certutil download").contains(&"sigma:certutil-1".to_string()));
        assert!(top("process injection").contains(&"attack:T1055".to_string()));
        // Author field is queryable ("rules by Florian Roth").
        assert!(top("Florian Roth").contains(&"sigma:shadow-1".to_string()));
    }

    #[test]
    fn persistence_reopen_yields_same_results() {
        let dir = tempfile::tempdir().unwrap();
        let a = {
            let idx = open_or_build(&corpus(), dir.path()).unwrap();
            bm25_search(&idx, "/etc/shadow", 5).unwrap()
        };
        // Reopen the SAME dir (no rebuild — fingerprint matches).
        let idx2 = open_or_build(&corpus(), dir.path()).unwrap();
        let b = bm25_search(&idx2, "/etc/shadow", 5).unwrap();
        assert_eq!(a, b, "reopen must yield identical ranked results");
        assert!(dir.path().join(FINGERPRINT_FILE).is_file());
    }

    #[test]
    fn fingerprint_is_deterministic_and_change_sensitive() {
        let c = corpus();
        assert_eq!(source_fingerprint(&c), source_fingerprint(&c));
        // id-set order independence.
        let mut shuffled = c.clone();
        shuffled.reverse();
        assert_eq!(source_fingerprint(&c), source_fingerprint(&shuffled));
        // content change ⇒ different fingerprint ⇒ triggers rebuild.
        let mut changed = c.clone();
        changed[0].content.push_str(" extra");
        assert_ne!(source_fingerprint(&c), source_fingerprint(&changed));
    }

    /// Opt-in end-to-end over the REAL P2 corpus (`target/kb/*.jsonl`,
    /// gitignored — produced by `cargo xtask rag-kb`) + the 6.7 seed.
    /// Mirrors the candle-bench discipline: needs an artifact CI does
    /// not have, so `#[ignore]`. Run: `cargo test -p northnarrow-agent
    /// -- --ignored real_corpus_smoke --nocapture`.
    #[test]
    #[ignore = "needs target/kb/*.jsonl from `cargo xtask rag-kb`"]
    fn real_corpus_smoke() {
        let kb = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("target/kb");
        if !kb.is_dir() {
            eprintln!("target/kb absent — run `cargo xtask rag-kb` first");
            return;
        }
        let recs = load_records(&kb, &crate::rag::kb_seed::seed_documents()).unwrap();
        eprintln!("real corpus: {} records (attack+sigma+seed)", recs.len());
        let dir = tempfile::tempdir().unwrap();
        let idx = open_or_build(&recs, dir.path()).unwrap();
        for q in [
            "T1059.001 powershell",
            "/etc/shadow",
            "xmrig cryptomining",
            "certutil download",
            "process injection",
        ] {
            let hits = bm25_search(&idx, q, 5).unwrap();
            eprintln!("  q={q:?} -> {:?}", hits.iter().map(|(_, i)| i).collect::<Vec<_>>());
            assert!(!hits.is_empty(), "no hits for {q:?} over the real corpus");
        }
    }

    #[test]
    fn rebuild_on_source_change() {
        let dir = tempfile::tempdir().unwrap();
        open_or_build(&corpus(), dir.path()).unwrap();
        let fp1 = std::fs::read_to_string(dir.path().join(FINGERPRINT_FILE)).unwrap();
        let mut c2 = corpus();
        c2.push(rec("sigma:new-1", "New Rule", "a brand new linux rule", None));
        let idx = open_or_build(&c2, dir.path()).unwrap();
        let fp2 = std::fs::read_to_string(dir.path().join(FINGERPRINT_FILE)).unwrap();
        assert_ne!(fp1, fp2, "fingerprint marker must update on rebuild");
        assert!(bm25_search(&idx, "brand new linux", 5)
            .unwrap()
            .iter()
            .any(|(_, id)| id == "sigma:new-1"));
    }
}
