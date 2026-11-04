//! One signed row, verified from its bytes alone (lot 276, the export).
//!
//! A receiver of the export holds a row as it was on the agent's disk (the
//! OCSF record's `raw_data`) and the agent's public key, not the row's
//! Rust type. Every chain writes its row with `serde_json` in its fields'
//! order, the seal last — `…,"prev_hash":"<hex>","entry_hash":"<hex>",
//! "agent_sig":"<base64>"}` — and signs the digest of the same bytes with
//! the seal's two values empty. So the pre-image is the row's bytes with
//! those two values blanked: [`verify_row`] rebuilds it, recomputes the
//! digest with the chain's domain, and checks the hash and the signature
//! (strict).
//!
//! It is sound without the type: a row verifies only if the agent's key
//! signed the digest of these very bytes (the seal aside), and the agent
//! signs only its rows' canonical serialisations. It may refuse a genuine
//! row the type's own check accepts — a v1/v2 row whose bytes were not
//! canonical (`chainlog`'s `non_canonical_legacy`): such a row is reported,
//! never accepted on a guess. `xtask`-free tests below hold it to the
//! writers': the rotating log's data lines and terminators, and the flat
//! chains' numbered rows.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::chain_anchor::{AUDIT_DOMAIN_V2, CANARY_ACCESS_DOMAIN_V2, CANARY_REGISTRY_DOMAIN_V2};
use crate::chainlog::{chain_domain, LineRole, CHAINLOG_FMT_V2, CHAINLOG_FMT_V3};

/// A row's place in its chain's links, and which line it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowSeal {
    /// A terminator (`{"rotate":…}`, the last line of a rotated file), or a
    /// data line.
    pub terminator: bool,
    pub prev_hash: String,
    pub entry_hash: String,
    /// Signed with its chain's domain: a v3 line of a rotating chain, a
    /// numbered row of a flat one.
    pub tagged: bool,
}

/// Why a row does not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowFault {
    /// Its bytes do not end in a seal (`prev_hash`, `entry_hash`,
    /// `agent_sig`, in that order, of their shapes).
    Shape(&'static str),
    /// The chain's name is not one this reader knows the domain of.
    Chain,
    /// The digest of its bytes is not its `entry_hash`.
    Hash { recomputed: String, stored: String },
    /// The signature does not verify with the key.
    Signature,
}

impl std::fmt::Display for RowFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RowFault::Shape(w) => write!(f, "not a sealed row: {w}"),
            RowFault::Chain => write!(f, "a chain this reader does not know"),
            RowFault::Hash { recomputed, stored } => {
                write!(f, "entry_hash {stored}, its bytes hash to {recomputed}")
            }
            RowFault::Signature => write!(f, "the signature does not verify"),
        }
    }
}

const PREV: &[u8] = b"\"prev_hash\":\"";
const ENTRY: &[u8] = b",\"entry_hash\":\"";
const SIG: &[u8] = b",\"agent_sig\":\"";
const BLANK_SEAL: &[u8] = b",\"entry_hash\":\"\",\"agent_sig\":\"\"}";

fn is_lower_hex(b: &[u8]) -> bool {
    b.iter()
        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
}

/// The row's seal split off: the bytes before `,"entry_hash"` (they end
/// with `prev_hash`'s value), `prev_hash`, `entry_hash`, `agent_sig`.
fn split(raw: &[u8]) -> Result<(&[u8], &str, &str, &str), RowFault> {
    let body = raw
        .strip_suffix(b"\"}")
        .ok_or(RowFault::Shape("its last bytes"))?;
    let at = body
        .windows(SIG.len())
        .rposition(|w| w == SIG)
        .ok_or(RowFault::Shape("no agent_sig"))?;
    let sig = body.get(at + SIG.len()..).unwrap_or_default();
    if sig.len() != 88
        || !sig
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'='))
    {
        return Err(RowFault::Shape("agent_sig"));
    }
    let before_sig = body.get(..at).unwrap_or_default();
    // `,"entry_hash":"` + 64 hex + `"`
    let entry_at = before_sig
        .len()
        .checked_sub(ENTRY.len() + 65)
        .ok_or(RowFault::Shape("entry_hash"))?;
    let (head, entry) = before_sig.split_at(entry_at);
    let hash = entry
        .strip_prefix(ENTRY)
        .and_then(|h| h.strip_suffix(b"\""))
        .filter(|h| h.len() == 64 && is_lower_hex(h))
        .ok_or(RowFault::Shape("entry_hash"))?;
    // `"prev_hash":"` + 64 hex + `"`, after `{` or `,`
    let prev_at = head
        .len()
        .checked_sub(PREV.len() + 65)
        .ok_or(RowFault::Shape("prev_hash"))?;
    let prev = head
        .get(prev_at..)
        .and_then(|p| p.strip_prefix(PREV))
        .and_then(|p| p.strip_suffix(b"\""))
        .filter(|p| p.len() == 64 && is_lower_hex(p))
        .ok_or(RowFault::Shape("prev_hash"))?;
    if !matches!(head.get(prev_at.wrapping_sub(1)), Some(b',' | b'{')) {
        return Err(RowFault::Shape("prev_hash is not a key of the row"));
    }
    fn text(b: &[u8]) -> Result<&str, RowFault> {
        std::str::from_utf8(b).map_err(|_| RowFault::Shape("not ASCII"))
    }
    Ok((head, text(prev)?, text(hash)?, text(sig)?))
}

/// Only the row's links, unverified: `(prev_hash, entry_hash)`.
pub fn links(raw: &[u8]) -> Option<(String, String)> {
    split(raw)
        .ok()
        .map(|(_, p, h, _)| (p.to_string(), h.to_string()))
}

/// What a flat chain's numbered rows are signed under.
fn flat_domain(chain: &str) -> Option<&'static [u8]> {
    match chain {
        "audit" => Some(AUDIT_DOMAIN_V2),
        "canary_registry" => Some(CANARY_REGISTRY_DOMAIN_V2),
        "canary_access" => Some(CANARY_ACCESS_DOMAIN_V2),
        _ => None,
    }
}

/// Whether `head` (a row up to its `prev_hash`) has the top-level key
/// `key` right before `prev_hash` with an unsigned integer value; the
/// value. A string's quote is always escaped, so `,"key":N,"prev_hash"`
/// cannot be the inside of a value.
fn key_before_prev(head: &[u8], key: &[u8]) -> Option<u64> {
    // `head` ends with `,"prev_hash":"<64 hex>"` (checked by `split`)
    let before = head.get(..head.len().checked_sub(PREV.len() + 65 + 1)?)?;
    let digits_at = before
        .iter()
        .rposition(|c| !c.is_ascii_digit())
        .map_or(0, |i| i + 1);
    let (lead, digits) = before.split_at(digits_at);
    let mut k = b",\"".to_vec();
    k.extend_from_slice(key);
    k.extend_from_slice(b"\":");
    if digits.is_empty() || !lead.ends_with(&k) {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}

/// A terminator's `rotate.fmt_ver`: its first key, always written.
fn terminator_fmt_ver(raw: &[u8]) -> Option<u64> {
    let rest = raw.strip_prefix(b"{\"rotate\":{\"fmt_ver\":")?;
    let n = rest.iter().position(|c| !c.is_ascii_digit())?;
    if n == 0 || rest.get(n) != Some(&b',') {
        return None;
    }
    std::str::from_utf8(&rest[..n]).ok()?.parse().ok()
}

/// Verify one row of the chain `chain` (its kind: `detections`, `actions`,
/// `fim_drift`, `netflow`, `canary_access`, …) from its bytes as they are
/// on disk, without the newline. Its link to the row before it is the
/// caller's: compare its `prev_hash` with that row's `entry_hash`.
pub fn verify_row(raw: &[u8], chain: &str, pk: &VerifyingKey) -> Result<RowSeal, RowFault> {
    let (head, prev, stored, sig) = split(raw)?;
    let terminator = raw.starts_with(b"{\"rotate\":");
    let domain: Option<Vec<u8>> = match flat_domain(chain) {
        Some(d) => {
            if terminator {
                return Err(RowFault::Shape("a terminator in a flat chain"));
            }
            key_before_prev(head, b"seq").map(|_| d.to_vec())
        }
        None => {
            let ver = if terminator {
                terminator_fmt_ver(raw)
                    .map(Some)
                    .ok_or(RowFault::Shape("a terminator's fmt_ver"))
            } else {
                Ok(key_before_prev(head, b"fmt_ver"))
            }?;
            // the chain log's own reading (`chainlog::pre_image`): none or up
            // to v2 untagged, v3 tagged, a later one a format unknown here
            let v3 = match ver {
                None => false,
                Some(v) if v <= u64::from(CHAINLOG_FMT_V2) => false,
                Some(v) if v == u64::from(CHAINLOG_FMT_V3) => true,
                Some(_) => return Err(RowFault::Shape("a fmt_ver this reader does not know")),
            };
            let role = if terminator {
                LineRole::Terminator
            } else {
                LineRole::Data
            };
            if v3 {
                Some(chain_domain(chain, role).map_err(|_| RowFault::Chain)?)
            } else {
                None
            }
        }
    };
    let prev_bytes = hex::decode(prev).map_err(|_| RowFault::Shape("prev_hash"))?;
    let mut h = Sha256::new();
    if let Some(d) = &domain {
        h.update(d);
    }
    h.update(&prev_bytes);
    h.update(head);
    h.update(BLANK_SEAL);
    let digest: [u8; 32] = h.finalize().into();
    let recomputed = hex::encode(digest);
    if recomputed != stored {
        return Err(RowFault::Hash {
            recomputed,
            stored: stored.to_string(),
        });
    }
    let sig = B64
        .decode(sig)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
        .ok_or(RowFault::Shape("agent_sig"))?;
    pk.verify_strict(&digest, &Signature::from_bytes(&sig))
        .map_err(|_| RowFault::Signature)?;
    Ok(RowSeal {
        terminator,
        prev_hash: prev.to_string(),
        entry_hash: stored.to_string(),
        tagged: domain.is_some(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_host::testing::TestKey;
    use crate::chain_host::ChainSigner;
    use crate::chainlog::{
        archive_path_for, line_is_genuine, ChainPayload, NoProtection, RotatingChainLog,
        RotationConfig,
    };
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct Pay {
        n: u64,
        text: String,
    }

    impl ChainPayload for Pay {
        const KIND: &'static str = "detections";
    }

    fn lines(path: &std::path::Path) -> Vec<Vec<u8>> {
        std::fs::read(path)
            .unwrap()
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(<[u8]>::to_vec)
            .collect()
    }

    /// The rotating log's own lines — data lines across a rotation and the
    /// terminator — verify from their bytes, as `line_is_genuine` says, and
    /// link.
    #[test]
    fn the_rotating_log_s_lines_verify_from_their_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("detections.jsonl");
        let k = TestKey::fresh();
        let pk = k.verifying_key();
        let mut log = RotatingChainLog::<Pay, _>::open(
            &active,
            k,
            RotationConfig {
                size_cap_bytes: 1200,
                max_archives: 64,
                file_mode: 0o600,
            },
            std::sync::Arc::new(NoProtection),
        )
        .unwrap();
        for n in 0..12 {
            log.append(Pay {
                n,
                // a payload that holds the seal's own spellings, escaped
                text: format!("\",\"prev_hash\":\"{n}\" \\ é \u{1}"),
            })
            .unwrap();
        }
        drop(log);
        let mut all = Vec::new();
        let mut archives = 0;
        for seq in 1.. {
            let a = archive_path_for(&active, seq);
            if !a.exists() {
                break;
            }
            let ls = lines(&a);
            assert!(ls.last().unwrap().starts_with(b"{\"rotate\":"));
            all.extend(ls);
            archives += 1;
        }
        assert!(
            archives >= 2,
            "rotated: {:?}",
            std::fs::read_dir(dir.path())
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect::<Vec<_>>()
        );
        all.extend(lines(&active));
        let mut prev: Option<String> = None;
        let mut terminators = 0;
        for l in &all {
            let seal = verify_row(l, "detections", &pk).unwrap_or_else(|e| {
                panic!("{e}: {}", String::from_utf8_lossy(l));
            });
            assert!(seal.tagged, "v3 lines");
            if seal.terminator {
                terminators += 1;
            } else {
                assert!(line_is_genuine::<Pay>(l, &pk));
            }
            if let Some(p) = &prev {
                assert_eq!(&seal.prev_hash, p, "linked");
            }
            assert_eq!(
                links(l),
                Some((seal.prev_hash.clone(), seal.entry_hash.clone()))
            );
            prev = Some(seal.entry_hash);
        }
        assert_eq!(terminators, archives);
        // another chain's name, another key: refused
        let first = &all[0];
        assert!(matches!(
            verify_row(first, "actions", &pk),
            Err(RowFault::Hash { .. })
        ));
        let other = TestKey::fresh().verifying_key();
        assert_eq!(
            verify_row(first, "detections", &other),
            Err(RowFault::Signature)
        );
        assert_eq!(verify_row(first, "NOT A KIND", &pk), Err(RowFault::Chain));
    }

    /// Every byte of a row is covered: one changed byte anywhere is refused.
    #[test]
    fn a_changed_byte_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("d.jsonl");
        let k = TestKey::fresh();
        let pk = k.verifying_key();
        let mut log = RotatingChainLog::<Pay, _>::open(
            &active,
            k,
            RotationConfig::default(),
            std::sync::Arc::new(NoProtection),
        )
        .unwrap();
        log.append(Pay {
            n: 7,
            text: "abc".into(),
        })
        .unwrap();
        drop(log);
        let row = lines(&active).remove(0);
        assert!(verify_row(&row, "detections", &pk).is_ok());
        for i in 0..row.len() {
            let mut bad = row.clone();
            bad[i] = if bad[i] == b'0' { b'1' } else { b'0' };
            assert!(
                verify_row(&bad, "detections", &pk).is_err(),
                "byte {i} of {}",
                String::from_utf8_lossy(&row)
            );
        }
        assert!(verify_row(&row[..row.len() - 1], "detections", &pk).is_err());
        assert!(verify_row(b"", "detections", &pk).is_err());
        assert!(verify_row(b"{}", "detections", &pk).is_err());
    }

    #[derive(Serialize)]
    struct FlatRow {
        ts: String,
        canary_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        seq: Option<u64>,
        prev_hash: String,
        entry_hash: String,
        agent_sig: String,
    }

    fn flat_row(k: &TestKey, seq: Option<u64>, prev: &str) -> Vec<u8> {
        let mut r = FlatRow {
            ts: "2026-11-03T00:00:00.000000Z".into(),
            canary_id: "c-1".into(),
            seq,
            prev_hash: prev.into(),
            entry_hash: String::new(),
            agent_sig: String::new(),
        };
        let body = serde_json::to_vec(&r).unwrap();
        let digest = crate::chain_anchor::flat_digest(
            seq.map(|_| CANARY_ACCESS_DOMAIN_V2),
            &r.prev_hash,
            &body,
        )
        .unwrap();
        r.entry_hash = hex::encode(digest);
        r.agent_sig = B64.encode(k.sign(&digest).to_bytes());
        serde_json::to_vec(&r).unwrap()
    }

    /// The flat chains: a numbered row under its domain, an older
    /// unnumbered one without.
    #[test]
    fn flat_rows_verify_with_and_without_their_number() {
        let k = TestKey::fresh();
        let pk = k.verifying_key();
        let genesis = "0".repeat(64);
        let old = flat_row(&k, None, &genesis);
        let s = verify_row(&old, "canary_access", &pk).unwrap();
        assert!(!s.tagged && !s.terminator);
        let numbered = flat_row(&k, Some(1), &s.entry_hash);
        let n = verify_row(&numbered, "canary_access", &pk).unwrap();
        assert!(n.tagged);
        assert_eq!(n.prev_hash, s.entry_hash);
        // under another flat chain's domain it does not verify
        assert!(verify_row(&numbered, "canary_registry", &pk).is_err());
        assert!(verify_row(&numbered, "audit", &pk).is_err());
    }

    #[test]
    fn shapes_are_refused_before_any_hash() {
        let k = TestKey::fresh();
        let pk = k.verifying_key();
        let genesis = "0".repeat(64);
        let row = flat_row(&k, Some(0), &genesis);
        let text = String::from_utf8(row).unwrap();
        for (what, bent) in [
            ("no closing", text.trim_end_matches('}').to_string()),
            (
                "short sig",
                text.replacen("\"agent_sig\":\"", "\"agent_sig\":\"A", 1),
            ),
            ("upper hex", text.replace(&genesis, &"A".repeat(64))),
            (
                "prev inside a value",
                text.replacen(",\"prev_hash\"", "x\"prev_hash\"", 1),
            ),
        ] {
            assert!(
                matches!(
                    verify_row(bent.as_bytes(), "canary_access", &pk),
                    Err(RowFault::Shape(_))
                ),
                "{what}"
            );
        }
    }

    /// A row sealed by hand the way the chain log seals its lines: the
    /// digest over `domain` (none for the legacy formats), `prev_hash`'s
    /// bytes and the JSON with an empty seal.
    fn sealed<T: Serialize>(
        k: &TestKey,
        domain: Option<Vec<u8>>,
        prev: &str,
        line: &mut T,
        seal: fn(&mut T) -> (&mut String, &mut String),
    ) -> Vec<u8> {
        let body = serde_json::to_vec(&*line).unwrap();
        let mut h = Sha256::new();
        if let Some(d) = &domain {
            h.update(d);
        }
        h.update(hex::decode(prev).unwrap());
        h.update(&body);
        let digest: [u8; 32] = h.finalize().into();
        let (e, a) = seal(line);
        *e = hex::encode(digest);
        *a = B64.encode(k.sign(&digest).to_bytes());
        serde_json::to_vec(&*line).unwrap()
    }

    #[derive(Serialize)]
    struct DataLine {
        n: u64,
        text: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        fmt_ver: Option<u32>,
        prev_hash: String,
        entry_hash: String,
        agent_sig: String,
    }

    #[derive(Serialize)]
    struct Rot {
        fmt_ver: u32,
        this_seq: u64,
        next_seq: u64,
        record_count: u64,
        bytes: u64,
    }

    #[derive(Serialize)]
    struct TermLine {
        rotate: Rot,
        ts: String,
        prev_hash: String,
        entry_hash: String,
        agent_sig: String,
    }

    fn data(k: &TestKey, fmt_ver: Option<u32>, domain: Option<Vec<u8>>) -> Vec<u8> {
        let prev = "1".repeat(64);
        let mut l = DataLine {
            n: 1,
            text: "a".into(),
            fmt_ver,
            prev_hash: prev.clone(),
            entry_hash: String::new(),
            agent_sig: String::new(),
        };
        sealed(k, domain, &prev, &mut l, |l| {
            (&mut l.entry_hash, &mut l.agent_sig)
        })
    }

    fn term(k: &TestKey, fmt_ver: u32, domain: Option<Vec<u8>>) -> Vec<u8> {
        let prev = "2".repeat(64);
        let mut l = TermLine {
            rotate: Rot {
                fmt_ver,
                this_seq: 1,
                next_seq: 2,
                record_count: 1,
                bytes: 100,
            },
            ts: "2026-11-03T00:00:00.000000Z".into(),
            prev_hash: prev.clone(),
            entry_hash: String::new(),
            agent_sig: String::new(),
        };
        sealed(k, domain, &prev, &mut l, |l| {
            (&mut l.entry_hash, &mut l.agent_sig)
        })
    }

    /// The rotating chains' formats as the chain log reads them: none or
    /// up to v2 untagged, v3 under the chain's domain, a later one refused;
    /// a terminator alike, by its `rotate.fmt_ver`.
    #[test]
    fn each_format_is_read_as_the_chain_log_reads_it() {
        let k = TestKey::fresh();
        let pk = k.verifying_key();
        let dom = |role| Some(chain_domain("detections", role).unwrap());
        for v in [None, Some(1), Some(CHAINLOG_FMT_V2)] {
            let row = data(&k, v, None);
            let seal = verify_row(&row, "detections", &pk).unwrap();
            assert!(!seal.tagged && !seal.terminator, "{v:?}");
            assert!(line_is_genuine::<Pay>(&row, &pk), "{v:?}");
            // a legacy row sealed under the domain is not what it says
            assert!(verify_row(&data(&k, v, dom(LineRole::Data)), "detections", &pk).is_err());
        }
        let row = data(&k, Some(CHAINLOG_FMT_V3), dom(LineRole::Data));
        assert!(verify_row(&row, "detections", &pk).unwrap().tagged);
        // a v3 row without its domain
        assert!(verify_row(&data(&k, Some(3), None), "detections", &pk).is_err());
        // a format this reader does not know, sealed either way
        for d in [None, dom(LineRole::Data)] {
            assert_eq!(
                verify_row(&data(&k, Some(4), d), "detections", &pk),
                Err(RowFault::Shape("a fmt_ver this reader does not know"))
            );
        }
        // terminators
        for v in [1, CHAINLOG_FMT_V2] {
            let t = term(&k, v, None);
            let seal = verify_row(&t, "detections", &pk).unwrap();
            assert!(seal.terminator && !seal.tagged, "{v}");
            assert!(
                verify_row(&term(&k, v, dom(LineRole::Terminator)), "detections", &pk).is_err()
            );
        }
        let t = term(&k, CHAINLOG_FMT_V3, dom(LineRole::Terminator));
        let seal = verify_row(&t, "detections", &pk).unwrap();
        assert!(seal.terminator && seal.tagged);
        // a terminator under the data lines' domain, or none
        assert!(verify_row(&term(&k, 3, dom(LineRole::Data)), "detections", &pk).is_err());
        assert!(verify_row(&term(&k, 3, None), "detections", &pk).is_err());
        assert_eq!(
            verify_row(&term(&k, 4, None), "detections", &pk),
            Err(RowFault::Shape("a fmt_ver this reader does not know"))
        );
        // a terminator whose `rotate` does not start with its fmt_ver
        #[derive(Serialize)]
        struct NoVer {
            this_seq: u64,
        }
        #[derive(Serialize)]
        struct NoVerLine {
            rotate: NoVer,
            prev_hash: String,
            entry_hash: String,
            agent_sig: String,
        }
        let prev = "3".repeat(64);
        let mut l = NoVerLine {
            rotate: NoVer { this_seq: 1 },
            prev_hash: prev.clone(),
            entry_hash: String::new(),
            agent_sig: String::new(),
        };
        let t = sealed(&k, None, &prev, &mut l, |l| {
            (&mut l.entry_hash, &mut l.agent_sig)
        });
        assert_eq!(
            verify_row(&t, "detections", &pk),
            Err(RowFault::Shape("a terminator's fmt_ver"))
        );
        // a terminator in a flat chain, however it is sealed
        for d in [None, Some(CANARY_ACCESS_DOMAIN_V2.to_vec())] {
            assert_eq!(
                verify_row(&term(&k, 2, d), "canary_access", &pk),
                Err(RowFault::Shape("a terminator in a flat chain"))
            );
        }
    }
}
