//! Glue between [`crate::rag`] and the ADE evaluator
//! (Sub-tappa 6.7).
//!
//! Two responsibilities:
//!
//! 1. Translate a focal [`Event`] into a short text query suitable
//!    for the embedder ([`build_rag_query_from_event`]).
//! 2. Render a [`RagResult`] as a compact `RAG_CONTEXT:` block to
//!    splice into the structured prompt ([`format_rag_block`]).
//!
//! The block is spliced into the **trusted** region of the prompt
//! (after `=== END TRUSTED CONTEXT ===`, before
//! `=== UNTRUSTED EVENT DATA ===` — see [`super::structured_prompt`]):
//! the model treats the retrieved KB summaries as curator-vetted
//! context, in contrast with the untrusted event data which must
//! never be treated as instructions. Trust is conveyed by placement
//! and the trained `RAG_CONTEXT:` convention, not by an inline tag.
//! The byte-exact shape of the block is a training contract — see
//! [`format_rag_block`].

use common::rag_types::{KbCategory, RagResult};
use common::Event;

/// Build a short, focused embedding query from a focal event.
///
/// Different event kinds project to different surface forms — e.g.
/// for a process spawn we use `comm` and `filename`, for a DNS
/// query we use the domain. Keep the query under ~120 chars to
/// stay within the embedder's hot path.
pub fn build_rag_query_from_event(event: &Event) -> String {
    match event {
        Event::ProcessSpawn { comm, filename, .. } => format!("process {comm} from {filename}"),
        Event::FileOpen { filename, .. } => format!("file open {filename}"),
        Event::ExecCheck { filename, .. } => format!("exec check {filename}"),
        Event::TcpConnect {
            comm,
            dst_addr,
            dst_port,
            ..
        } => {
            let ip = format_ip(dst_addr);
            format!("tcp connect from {comm} to {ip} port {dst_port}")
        }
        Event::DnsQuery {
            comm, query_name, ..
        } => format!("dns query from {comm} to {query_name}"),
        Event::FsProtectDenial {
            comm, operation, ..
        } => format!("anti-tamper denial of {operation} by {comm}"),
        // Tappa 9 (C4): FIM drift RAG query — keep short, focus
        // on path + op (the most-grep-able tokens for sigma-rule
        // search). Doesn't reach RAG in V1.0.
        Event::Fim(fe) => format!("fim drift {} op {:?}", fe.path, fe.op),
    }
}

/// Sigma rule severity, recovered from [`RagDocument::content`].
///
/// A typed enum (rather than a raw `&str`) so the prompt-line builder
/// cannot typo the token; [`Display`](core::fmt::Display) emits the
/// canonical lowercase Sigma form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigmaSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for SigmaSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SigmaSeverity::Low => "low",
            SigmaSeverity::Medium => "medium",
            SigmaSeverity::High => "high",
            SigmaSeverity::Critical => "critical",
        })
    }
}

/// Deterministically recover a Sigma rule's severity from the indexed
/// `content` body, or `None` if it is not reliably present.
///
/// The authoritative marker is the standalone `Level: <level>` line
/// the P2 canonical builder appends for real Sigma-HQ rules
/// (`xtask/src/rag_kb.rs` — `content.push_str("\nLevel: {level}")`,
/// where `level` is the canonical lowercase Sigma `level:` field). We
/// also accept a standalone `Severity: <level>` line for symmetry.
///
/// Recovery is a **whole-line prefix** match against an **exact**
/// token — never a substring scan ("high" anywhere in an attack
/// description would be a false positive). Anything else — the
/// in-repo curated-seed inline prose form, Sigma `informational`, a
/// compound like `medium-to-high` — yields `None`, and the caller
/// falls back to the title-only `Sigma Intel:` form. Zero false
/// positives by construction.
fn extract_sigma_severity(content: &str) -> Option<SigmaSeverity> {
    for raw in content.lines() {
        let line = raw.trim();
        let val = match line
            .strip_prefix("Level:")
            .or_else(|| line.strip_prefix("Severity:"))
        {
            Some(v) => v.trim().trim_end_matches('.').trim(),
            None => continue,
        };
        match val {
            "low" => return Some(SigmaSeverity::Low),
            "medium" => return Some(SigmaSeverity::Medium),
            "high" => return Some(SigmaSeverity::High),
            "critical" => return Some(SigmaSeverity::Critical),
            _ => continue,
        }
    }
    None
}

/// Normalise a doc title to exactly one trailing period (training-data
/// convention): strip trailing whitespace / `.` then append a single
/// `.`.
fn clean_title(title: &str) -> String {
    let core = title.trim().trim_end_matches('.').trim_end();
    format!("{core}.")
}

/// # Phase-A/B/C/D training contract (Tappa 6.9.7.1 P5.1, 2026-05-19)
///
/// AMENDS the P5 (Tappa 6.9.7, 2026-05-17) freeze ruling.
///
/// Emits the compact "RAG_CONTEXT:\n<lines>\n\n" block matching the
/// natural-language training format used across Phase A/B/D
/// (Sigma Intel / Intel: prefixes, single line per retrieved doc).
/// Phase C (customer-context whitelisting) uses an orthogonal
/// pattern not emitted by production retrieval — intentional, see
/// resilience-training rationale in XDR plan §5.2.
///
/// Sigma severity: recovered via deterministic parse of
/// RagDocument.content per index_tantivy.rs SigmaRule indexing
/// convention. Recovery failure → graceful fallback to title-only
/// "Sigma Intel: {title}." form. See extract_sigma_severity.
///
/// Top-K projection: one line per retrieved doc (Option B). Model
/// trained on single-line RAG_CONTEXT examples; multi-line is OOD
/// but expected robust per base-model pretraining. Canary
/// NN_ADE_RAG_ENABLED defaults OFF; pre-beta validation will
/// observe behavior under multi-doc retrieval before any flip.
///
/// The `format_rag_block_byte_stable_phase_abcd_contract` regression
/// test locks the byte-exact output for a synthetic 3-doc input.
/// Article 13 per-doc id/category/similarity traceability is
/// delegated to backend log sink (Tappa 13), NOT to the prompt.
///
/// Returns `None` for an empty/`None` `RagResult` so the caller skips
/// the section entirely (no `RAG_CONTEXT:` header, byte-identical to
/// the pre-6.7 / `rag:None` path). The `Option<String>` signature is
/// preserved deliberately — see the P5.1 reconciliation note in the
/// commit body.
pub fn format_rag_block(result: &RagResult) -> Option<String> {
    if result.is_empty() {
        return None;
    }

    let mut out = String::with_capacity(256);
    out.push_str("RAG_CONTEXT:\n");

    for doc in &result.documents {
        let title = clean_title(&doc.title);
        let line = match doc.category {
            KbCategory::SigmaRule => match extract_sigma_severity(&doc.content) {
                Some(sev) => format!("Sigma Intel ({sev} severity): {title}"),
                None => format!("Sigma Intel: {title}"),
            },
            KbCategory::MitreTechnique
            | KbCategory::ThreatTool
            | KbCategory::Lolbas
            | KbCategory::LinuxPattern => format!("Intel: {title}"),
        };
        out.push_str(&line);
        out.push('\n');
    }

    // Trailing blank line: the old block ended "...===\n\n"; the
    // caller (structured_prompt.rs:91-95) splices this verbatim
    // immediately before "=== UNTRUSTED EVENT DATA ===" with no
    // separator of its own, so the "\n\n" preserves prompt spacing.
    out.push('\n');
    Some(out)
}

fn format_ip(raw: &[u8; 16]) -> String {
    // Heuristic: if the last 12 bytes are zero, treat as IPv4 in the
    // first 4 bytes (matches the eBPF wire layout for v4 events).
    if raw[4..].iter().all(|b| *b == 0) {
        format!("{}.{}.{}.{}", raw[0], raw[1], raw[2], raw[3])
    } else {
        // Coarse hex render — good enough for embedding queries.
        let mut s = String::with_capacity(40);
        for (i, b) in raw.iter().enumerate() {
            if i > 0 && i % 2 == 0 {
                s.push(':');
            }
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::rag_types::RagDocument;

    #[test]
    fn process_spawn_query_uses_comm_and_filename() {
        let e = Event::ProcessSpawn {
            pid: 1,
            ppid: 0,
            uid: 0,
            gid: 0,
            comm: "xmrig".into(),
            filename: "/tmp/.cache/x".into(),
            timestamp_ns: 0,
        };
        let q = build_rag_query_from_event(&e);
        assert!(q.contains("xmrig"));
        assert!(q.contains("/tmp/.cache/x"));
    }

    #[test]
    fn dns_query_uses_qname() {
        let e = Event::DnsQuery {
            pid: 1,
            uid: 1000,
            comm: "curl".into(),
            query_name: "evil.example.org".into(),
            query_type: 1,
            dns_server: [0u8; 16],
            family: 2,
            timestamp_ns: 0,
        };
        let q = build_rag_query_from_event(&e);
        assert!(q.contains("evil.example.org"));
        assert!(q.contains("curl"));
    }

    #[test]
    fn tcp_connect_uses_ip_and_port() {
        let mut dst = [0u8; 16];
        dst[..4].copy_from_slice(&[10, 0, 0, 1]);
        let e = Event::TcpConnect {
            pid: 1,
            uid: 0,
            comm: "nc".into(),
            family: 2,
            src_addr: [0u8; 16],
            src_port: 0,
            dst_addr: dst,
            dst_port: 4444,
            timestamp_ns: 0,
        };
        let q = build_rag_query_from_event(&e);
        assert!(q.contains("10.0.0.1"));
        assert!(q.contains("4444"));
    }

    #[test]
    fn empty_rag_result_renders_no_block() {
        let r = RagResult::default();
        // Empty ⇒ None ⇒ caller skips the section entirely (the
        // `Option` signature is preserved — see P5.1 doc-comment).
        assert!(format_rag_block(&r).is_none());
    }

    #[test]
    fn non_empty_rag_result_renders_compact_block() {
        let mut r = RagResult::default();
        r.documents.push(RagDocument {
            id: "sigma_xmrig_detection".into(),
            category: KbCategory::SigmaRule,
            title: "Sigma: Cryptominer Process Names".into(),
            content: "Detects known miner process names.\nLevel: high".into(),
            similarity: 0.81,
        });
        r.documents.push(RagDocument {
            id: "tool_cobaltstrike".into(),
            category: KbCategory::ThreatTool,
            title: "Cobalt Strike".into(),
            content: "Cobalt Strike is a commercial adversary simulation framework.".into(),
            similarity: 0.42,
        });
        let block = format_rag_block(&r).expect("non-empty ⇒ Some");
        assert!(block.starts_with("RAG_CONTEXT:\n"));
        assert!(block.contains("\nSigma Intel (high severity): Sigma: Cryptominer Process Names.\n"));
        assert!(block.contains("\nIntel: Cobalt Strike.\n"));
        assert!(block.ends_with("\n\n"));
        // Old P5 markers are gone.
        assert!(!block.contains("=== RELEVANT CYBERSEC KNOWLEDGE"));
        assert!(!block.contains("=== END RELEVANT KNOWLEDGE"));
        assert!(!block.contains("Similarity:"));
        assert!(!block.contains("Category:"));
    }

    #[test]
    fn severity_parse_low() {
        assert_eq!(
            extract_sigma_severity("desc\nLogsource: linux/-/-\nLevel: low"),
            Some(SigmaSeverity::Low)
        );
    }

    #[test]
    fn severity_parse_medium() {
        assert_eq!(
            extract_sigma_severity("desc\nLevel: medium"),
            Some(SigmaSeverity::Medium)
        );
    }

    #[test]
    fn severity_parse_high() {
        // `Severity:` variant + a defensive trailing period.
        assert_eq!(
            extract_sigma_severity("desc\nSeverity: high."),
            Some(SigmaSeverity::High)
        );
    }

    #[test]
    fn severity_parse_critical() {
        assert_eq!(
            extract_sigma_severity("desc\nLevel: critical"),
            Some(SigmaSeverity::Critical)
        );
    }

    #[test]
    fn severity_parse_missing_returns_none() {
        // No standalone Level:/Severity: line — the in-repo curated
        // seed inline-prose form ("... Severity: high. False ...") is
        // *not* its own line, so it correctly degrades to None.
        assert_eq!(
            extract_sigma_severity(
                "Detection: process where X. Severity: high. False positives: none."
            ),
            None
        );
    }

    #[test]
    fn severity_parse_malformed_returns_none() {
        // Compound / unknown tokens must NOT partial-match.
        assert_eq!(
            extract_sigma_severity("desc\nLevel: medium-to-high"),
            None
        );
        assert_eq!(extract_sigma_severity("desc\nLevel: bogus"), None);
        assert_eq!(extract_sigma_severity("desc\nLevel:"), None);
    }
}
