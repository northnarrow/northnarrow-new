//! Lot 374: the watchdog's witness chain — what the surviving role signs
//! of the other one's vacancy and of the process that takes it.
//!
//! The watchdog holds a signing key of its own for its life: made at its
//! start, kept in its memory only, its public half published in a sealed
//! memory file of the watchdog's ([`KEY_MEMFD_NAME`], one [`key_record`]
//! line). The agent reads that half from the verified watchdog's own
//! descriptor table — no other process can put a file there — and certifies
//! it in its signed audit chain; a key no agent certified is never trusted.
//!
//! Each [`Row`] names the key that signed it and the hash of the line before
//! it ([`line_hash`]), so the file is a chain: a row removed or changed
//! breaks it. The rows are the watchdog's own record when the agent dies
//! (the vacancy, its cause when known) and when a successor takes the role
//! (who it is, where it was started, what its environment and mappings
//! show) — never the successor's to write or to leave out. The agent
//! imports the rows it can verify into its own chain.
//!
//! Only names, numbers and paths are recorded, never a variable's value.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The directory of the witness chain, in the agent's state directory
/// (the agent's deny hooks keep it from every process outside the family).
pub const WITNESS_DIR: &str = "/var/lib/northnarrow/witness";
/// The chain's file in [`WITNESS_DIR`].
pub const CHAIN_FILE: &str = "witness.chain";
/// The agent's import position in [`WITNESS_DIR`] (the keys it certified
/// and the hash of the last row it imported).
pub const IMPORTED_FILE: &str = "witness.imported";
/// The name of the watchdog's sealed memory file that holds its key's
/// public half (`/memfd:<name>` in its descriptor table).
pub const KEY_MEMFD_NAME: &str = "nn-witness-key";
/// The first word of [`key_record`].
pub const KEY_RECORD_MAGIC: &str = "nn-witness-key-v1";
/// The largest chain the agent reads (far above a host's restarts).
pub const CHAIN_MAX_BYTES: u64 = 1 << 20;
/// The rows' format.
pub const ROW_VERSION: u32 = 1;

/// A watchdog life's first row: its key, and the chain head it continues.
pub const KIND_OPENED: &str = "witness_opened";
/// The agent's role fell vacant: its holder exited (the cause, when known).
pub const KIND_VACATED: &str = "role_vacated";
/// A process took the agent's vacated role: who it is and what it shows.
pub const KIND_SUCCEEDED: &str = "role_succeeded";
/// The watchdog's start found the agent's role vacated and no agent: both
/// roles were vacant.
pub const KIND_FOUND_VACANT: &str = "role_found_vacant";

/// One row of the witness chain (one JSON line).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    pub v: u32,
    /// Its place in the file, from 0.
    pub seq: u64,
    /// [`line_hash`] of the line before it; empty for the file's first.
    pub prev: String,
    /// Unix seconds.
    pub at: u64,
    /// The watchdog that signed it.
    pub tgid: u32,
    /// The signing key's public half (hex).
    pub key: String,
    pub kind: String,
    pub detail: String,
    /// The signature (hex) over [`Row::unsigned_bytes`].
    #[serde(default)]
    pub sig: String,
}

impl Row {
    /// What the signature covers: the row's JSON with `sig` empty.
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        let mut r = self.clone();
        r.sig = String::new();
        serde_json::to_vec(&r).unwrap_or_default()
    }

    /// One line: what a record shows of it.
    pub fn describe(&self) -> String {
        format!(
            "watchdog {} at {}: {}: {} [witness row {}, key {}]",
            self.tgid,
            self.at,
            self.kind,
            self.detail,
            self.seq,
            &self.key.get(..16).unwrap_or(&self.key)
        )
    }
}

/// The hex SHA-256 of a chain line (without its newline).
pub fn line_hash(line: &str) -> String {
    hex::encode(Sha256::digest(line.as_bytes()))
}

/// The watchdog's witness key, made from 32 random bytes at its start.
pub struct WitnessKey(SigningKey);

impl WitnessKey {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        WitnessKey(SigningKey::from_bytes(&seed))
    }

    /// The public half (hex).
    pub fn public_hex(&self) -> String {
        hex::encode(self.0.verifying_key().to_bytes())
    }

    /// `row` signed: its `key` set to this key's, then its `sig`.
    pub fn sign(&self, mut row: Row) -> Row {
        row.key = self.public_hex();
        row.sig = String::new();
        let sig = self.0.sign(&row.unsigned_bytes());
        row.sig = hex::encode(sig.to_bytes());
        row
    }
}

/// The line the watchdog's sealed memory file holds:
/// `nn-witness-key-v1 <tgid> <start ticks> <public half>`.
pub fn key_record(tgid: u32, start_ticks: u64, public_hex: &str) -> String {
    format!("{KEY_RECORD_MAGIC} {tgid} {start_ticks} {public_hex}\n")
}

/// [`key_record`] read back: `(tgid, start ticks, public half)` when it is
/// one and its key is a valid Ed25519 public key.
pub fn parse_key_record(text: &str) -> Option<(u32, u64, String)> {
    let mut w = text.trim_end_matches('\n').split(' ');
    if w.next()? != KEY_RECORD_MAGIC {
        return None;
    }
    let tgid = w.next()?.parse().ok()?;
    let start = w.next()?.parse().ok()?;
    let key = w.next()?.to_string();
    if w.next().is_some() || verifying_key(&key).is_none() {
        return None;
    }
    Some((tgid, start, key))
}

fn verifying_key(hex_key: &str) -> Option<VerifyingKey> {
    let b: [u8; 32] = hex::decode(hex_key).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&b).ok()
}

/// `row`'s signature verifies under the key it names.
pub fn signature_ok(row: &Row) -> bool {
    let (Some(k), Some(sig)) = (
        verifying_key(&row.key),
        hex::decode(&row.sig)
            .ok()
            .and_then(|b| <[u8; 64]>::try_from(b).ok()),
    ) else {
        return false;
    };
    k.verify(&row.unsigned_bytes(), &Signature::from_bytes(&sig))
        .is_ok()
}

/// One line of a chain, judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Judged {
    /// Signed by its key, linked to the line before it.
    Valid { row: Row, hash: String },
    /// Not a row, a signature that does not verify, or a link to another
    /// line than the one before it: the chain is broken from here.
    Broken { line: usize, why: String },
}

/// Every line of a chain text, in order, each judged against the line
/// before it; judging stops at the first broken one (what follows is not
/// the chain's).
pub fn judge_chain(text: &str) -> Vec<Judged> {
    let mut out = Vec::new();
    let mut prev = String::new();
    let mut expect_seq = 0u64;
    for (i, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let row: Row = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(_) => {
                out.push(Judged::Broken {
                    line: i + 1,
                    why: "not a witness row".to_string(),
                });
                return out;
            }
        };
        let why = if row.v != ROW_VERSION {
            Some("another format")
        } else if !signature_ok(&row) {
            Some("its signature does not verify")
        } else if row.prev != prev {
            Some("it does not follow the line before it")
        } else if row.seq != expect_seq {
            Some("its number is not the next")
        } else {
            None
        };
        if let Some(why) = why {
            out.push(Judged::Broken {
                line: i + 1,
                why: why.to_string(),
            });
            return out;
        }
        prev = line_hash(line);
        expect_seq = row.seq + 1;
        out.push(Judged::Valid {
            row,
            hash: prev.clone(),
        });
    }
    out
}

/// The import position the agent keeps ([`IMPORTED_FILE`]): the keys it
/// certified (newest last) and the hash of the last row it imported.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Imported {
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default)]
    pub last: String,
}

/// How many certified keys [`Imported`] keeps (a watchdog's restarts).
pub const KEYS_KEPT: usize = 32;

impl Imported {
    /// `key` certified (kept once, the oldest dropped past [`KEYS_KEPT`]).
    pub fn certify(&mut self, key: &str) -> bool {
        if self.keys.iter().any(|k| k == key) {
            return false;
        }
        self.keys.push(key.to_string());
        if self.keys.len() > KEYS_KEPT {
            self.keys.remove(0);
        }
        true
    }

    pub fn certified(&self, key: &str) -> bool {
        self.keys.iter().any(|k| k == key)
    }
}

/// What the agent records of a chain against its position: the rows after
/// the last one it imported, each certified or not, and where the chain
/// broke. When the last imported row is no longer in the chain (the file
/// was replaced or cut), every row is new and that is said too.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ToImport {
    pub rows: Vec<(Row, String, bool)>,
    pub broken: Option<String>,
    pub position_lost: bool,
}

pub fn to_import(text: &str, imported: &Imported) -> ToImport {
    let judged = judge_chain(text);
    let mut out = ToImport::default();
    let mut valid: Vec<(Row, String)> = Vec::new();
    for j in judged {
        match j {
            Judged::Valid { row, hash } => valid.push((row, hash)),
            Judged::Broken { line, why } => {
                out.broken = Some(format!("line {line}: {why}"));
            }
        }
    }
    let start = if imported.last.is_empty() {
        0
    } else {
        match valid.iter().position(|(_, h)| *h == imported.last) {
            Some(i) => i + 1,
            None => {
                out.position_lost = true;
                0
            }
        }
    };
    for (row, hash) in valid.into_iter().skip(start) {
        let ok = imported.certified(&row.key);
        out.rows.push((row, hash, ok));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> WitnessKey {
        WitnessKey::from_seed([b; 32])
    }

    fn row(seq: u64, prev: &str, kind: &str) -> Row {
        Row {
            v: ROW_VERSION,
            seq,
            prev: prev.to_string(),
            at: 1_700_000_000 + seq,
            tgid: 77,
            key: String::new(),
            kind: kind.to_string(),
            detail: format!("detail {seq}"),
            sig: String::new(),
        }
    }

    /// A chain of `n` rows signed by `k`, as lines.
    fn chain(k: &WitnessKey, n: u64) -> Vec<String> {
        let mut lines = Vec::new();
        let mut prev = String::new();
        for i in 0..n {
            let r = k.sign(row(i, &prev, KIND_VACATED));
            let l = serde_json::to_string(&r).unwrap();
            prev = line_hash(&l);
            lines.push(l);
        }
        lines
    }

    #[test]
    fn a_signed_chain_verifies_row_by_row() {
        let k = key(1);
        let text = chain(&k, 4).join("\n") + "\n";
        let j = judge_chain(&text);
        assert_eq!(j.len(), 4);
        assert!(j.iter().all(|x| matches!(x, Judged::Valid { .. })));
    }

    #[test]
    fn a_changed_removed_or_forged_row_breaks_the_chain() {
        let k = key(1);
        let lines = chain(&k, 4);
        // a detail changed after signing
        let mut changed = lines.clone();
        changed[1] = changed[1].replace("detail 1", "detail X");
        let j = judge_chain(&changed.join("\n"));
        assert!(matches!(j.last(), Some(Judged::Broken { line: 2, .. })), "{j:?}");
        // a row removed
        let mut removed = lines.clone();
        removed.remove(1);
        let j = judge_chain(&removed.join("\n"));
        assert!(matches!(j.last(), Some(Judged::Broken { line: 2, .. })), "{j:?}");
        // a row signed by another key in its place: valid signature, but a
        // key the agent never certified (see the import test)
        let other = key(2);
        let prev = line_hash(&lines[0]);
        let forged = serde_json::to_string(&other.sign(row(1, &prev, KIND_SUCCEEDED))).unwrap();
        let j = judge_chain(&[lines[0].clone(), forged].join("\n"));
        assert!(j.iter().all(|x| matches!(x, Judged::Valid { .. })));
        // a signature of another row's
        let mut swapped: Row = serde_json::from_str(&lines[1]).unwrap();
        swapped.sig = serde_json::from_str::<Row>(&lines[2]).unwrap().sig;
        let j = judge_chain(&[lines[0].clone(), serde_json::to_string(&swapped).unwrap()].join("\n"));
        assert!(matches!(j.last(), Some(Judged::Broken { line: 2, .. })), "{j:?}");
        // not JSON
        assert!(matches!(judge_chain("x").last(), Some(Judged::Broken { line: 1, .. })));
    }

    #[test]
    fn the_import_takes_the_rows_after_its_position_and_trusts_only_certified_keys() {
        let k = key(1);
        let lines = chain(&k, 3);
        let text = lines.join("\n") + "\n";
        let mut imp = Imported::default();
        // no key certified: rows are new, none trusted
        let t = to_import(&text, &imp);
        assert_eq!(t.rows.len(), 3);
        assert!(t.rows.iter().all(|(_, _, ok)| !ok));
        assert!(imp.certify(&k.public_hex()));
        assert!(!imp.certify(&k.public_hex()), "once");
        let t = to_import(&text, &imp);
        assert!(t.rows.iter().all(|(_, _, ok)| *ok));
        // after the second row
        imp.last = t.rows[1].1.clone();
        let t = to_import(&text, &imp);
        assert_eq!(t.rows.len(), 1);
        assert_eq!(t.rows[0].0.seq, 2);
        assert!(!t.position_lost);
        // the position gone (the file replaced): every row again, said
        imp.last = "00".repeat(32);
        let t = to_import(&text, &imp);
        assert_eq!(t.rows.len(), 3);
        assert!(t.position_lost);
    }

    #[test]
    fn the_key_record_round_trips_and_refuses_what_is_not_one() {
        let k = key(3);
        let rec = key_record(42, 1234, &k.public_hex());
        assert_eq!(parse_key_record(&rec), Some((42, 1234, k.public_hex())));
        assert_eq!(parse_key_record("nn-witness-key-v1 42 1234 zz"), None);
        assert_eq!(parse_key_record(&format!("other 42 1234 {}", k.public_hex())), None);
        assert_eq!(parse_key_record(&format!("{} extra", rec.trim_end())), None);
    }

    #[test]
    fn the_certified_keys_are_bounded() {
        let mut imp = Imported::default();
        for i in 0..(KEYS_KEPT as u8 + 5) {
            imp.certify(&key(i).public_hex());
        }
        assert_eq!(imp.keys.len(), KEYS_KEPT);
        assert!(!imp.certified(&key(0).public_hex()));
        assert!(imp.certified(&key(KEYS_KEPT as u8 + 4).public_hex()));
    }
}
