//! The scan of one file (lab PR 223): SHA-256 of the whole file, the signed
//! block and allow lists, then the format heuristics on its first bytes.

use std::collections::HashMap;
use std::io;
use std::time::Instant;

use common::execq::{
    Reason, ScanConfig, ScanRequest, ScanResult, ScanVerdict, ScannerHello, DEFAULT_MAX_HASH_BYTES,
    DEFAULT_MAX_READ_BYTES, DEFAULT_SUSPICIOUS_THRESHOLD, PROTOCOL_VERSION,
};
use sha2::{Digest, Sha256};

use crate::heuristics;

/// Read in pieces of this size past the in-memory prefix.
const CHUNK: usize = 1 << 20;

/// A file the engine reads by offset (a descriptor, or bytes in tests).
pub trait ReadAt {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize>;
    /// Size when the scan starts.
    fn size(&self) -> io::Result<u64>;
}

impl ReadAt for [u8] {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        let Ok(start) = usize::try_from(off) else {
            return Ok(0);
        };
        let Some(rest) = self.get(start..) else {
            return Ok(0);
        };
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        Ok(n)
    }
    fn size(&self) -> io::Result<u64> {
        Ok(self.len() as u64)
    }
}

/// The configured engine.
#[derive(Debug, Clone)]
pub struct Engine {
    block: HashMap<[u8; 32], String>,
    allow: HashMap<[u8; 32], String>,
    threshold: u32,
    max_read: u64,
    max_hash: u64,
    yara: String,
}

impl Engine {
    pub fn new(cfg: &ScanConfig) -> Self {
        let yara = match &cfg.yara_rules {
            None => "none".to_string(),
            Some(pack) => format!(
                "not built ({} bytes of rules ignored; docs/design/EXEC_QUARANTINE.md §6)",
                pack.len()
            ),
        };
        Engine {
            block: cfg
                .block
                .iter()
                .map(|e| (e.sha256, e.label.clone()))
                .collect(),
            allow: cfg
                .allow
                .iter()
                .map(|e| (e.sha256, e.label.clone()))
                .collect(),
            threshold: if cfg.suspicious_threshold == 0 {
                DEFAULT_SUSPICIOUS_THRESHOLD
            } else {
                cfg.suspicious_threshold
            },
            max_read: if cfg.max_read_bytes == 0 {
                DEFAULT_MAX_READ_BYTES
            } else {
                cfg.max_read_bytes
            },
            max_hash: if cfg.max_hash_bytes == 0 {
                DEFAULT_MAX_HASH_BYTES
            } else {
                cfg.max_hash_bytes
            },
            yara,
        }
    }

    /// Bytes held in memory at most for one scan.
    pub fn max_read(&self) -> u64 {
        self.max_read
    }

    pub fn hello(&self, uid: u32, seccomp: bool) -> ScannerHello {
        ScannerHello {
            version: PROTOCOL_VERSION,
            engine: format!(
                "northnarrow-scan {}: sha256, hash lists, elf heuristics",
                env!("CARGO_PKG_VERSION")
            ),
            uid,
            seccomp,
            block_entries: self.block.len() as u32,
            allow_entries: self.allow.len() as u32,
            yara: self.yara.clone(),
        }
    }

    /// Scan the file `src` describes.
    pub fn scan<R: ReadAt + ?Sized>(&self, src: &R, req: &ScanRequest) -> ScanResult {
        let started = Instant::now();
        let mut result = ScanResult {
            id: req.id,
            sha256: [0; 32],
            size: 0,
            verdict: ScanVerdict::Unscanned,
            reasons: Vec::new(),
            format: "unknown".to_string(),
            micros: 0,
        };
        let finish = |mut r: ScanResult| {
            r.micros = started.elapsed().as_micros() as u64;
            r
        };
        let size = match src.size() {
            Ok(s) => s,
            Err(e) => {
                result
                    .reasons
                    .push(Reason::new("io", format!("size: {e}"), 0));
                return finish(result);
            }
        };
        result.size = size;
        if size > self.max_hash {
            result.reasons.push(Reason::new(
                "too_large",
                format!("{size} bytes, over the {}-byte limit", self.max_hash),
                0,
            ));
            return finish(result);
        }
        // The prefix the heuristics read, then the rest for the digest.
        let keep = usize::try_from(size.min(self.max_read)).unwrap_or(0);
        let mut prefix = vec![0u8; keep];
        let mut hasher = Sha256::new();
        let mut got = 0usize;
        while got < keep {
            match src.read_at(&mut prefix[got..], got as u64) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    result
                        .reasons
                        .push(Reason::new("io", format!("read at {got}: {e}"), 0));
                    return finish(result);
                }
            }
        }
        prefix.truncate(got);
        hasher.update(&prefix);
        let mut total = got as u64;
        if got == keep && total < size {
            let mut buf = vec![0u8; CHUNK];
            loop {
                match src.read_at(&mut buf, total) {
                    Ok(0) => break,
                    Ok(n) => {
                        hasher.update(&buf[..n]);
                        total += n as u64;
                        if total > self.max_hash {
                            result.reasons.push(Reason::new(
                                "too_large",
                                format!("grew past the {}-byte limit while read", self.max_hash),
                                0,
                            ));
                            return finish(result);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => {
                        result
                            .reasons
                            .push(Reason::new("io", format!("read at {total}: {e}"), 0));
                        return finish(result);
                    }
                }
            }
        }
        result.size = total;
        result.sha256 = hasher.finalize().into();

        if let Some(label) = self.block.get(&result.sha256) {
            result.verdict = ScanVerdict::Malicious;
            result
                .reasons
                .push(Reason::new("blocklist", label.clone(), 0));
        } else if let Some(label) = self.allow.get(&result.sha256) {
            result.verdict = ScanVerdict::Trusted;
            result
                .reasons
                .push(Reason::new("allowlist", label.clone(), 0));
        }
        let findings = heuristics::assess(&prefix, total, req.class);
        result.format = findings.format.clone();
        if result.verdict == ScanVerdict::Unscanned {
            result.verdict = if findings.score() >= self.threshold {
                ScanVerdict::Suspicious
            } else {
                ScanVerdict::Clean
            };
        }
        // An allow-listed file is not judged; its findings are still told.
        result.reasons.extend(findings.reasons);
        if (total as usize) > prefix.len() {
            result.reasons.push(Reason::new(
                "partial_heuristics",
                format!("heuristics on the first {} of {total} bytes", prefix.len()),
                0,
            ));
        }
        finish(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::fixtures::*;
    use crate::elf::{ET_EXEC, PF_R, PF_W, PF_X, PT_LOAD};
    use common::execq::HashEntry;
    use common::wire::execq::class;

    fn req() -> ScanRequest {
        ScanRequest {
            id: 9,
            class: class::TMP,
            path_hint: "/tmp/x".into(),
        }
    }

    fn sha(b: &[u8]) -> [u8; 32] {
        Sha256::digest(b).into()
    }

    #[test]
    fn hash_covers_the_whole_file_beyond_the_prefix() {
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let e = Engine::new(&ScanConfig {
            max_read_bytes: 4096,
            ..ScanConfig::default()
        });
        let r = e.scan(data.as_slice(), &req());
        assert_eq!(r.sha256, sha(&data));
        assert_eq!(r.size, data.len() as u64);
        assert_eq!(r.verdict, ScanVerdict::Clean);
        assert!(r.reasons.iter().any(|x| x.code == "partial_heuristics"));
        assert_eq!(r.id, 9);
    }

    #[test]
    fn block_wins_over_allow_and_heuristics() {
        let data = b"\x7fELF-not-really".to_vec();
        let cfg = ScanConfig {
            block: vec![HashEntry {
                sha256: sha(&data),
                label: "nn-lab-test-elf".into(),
            }],
            ..ScanConfig::default()
        };
        let r = Engine::new(&cfg).scan(data.as_slice(), &req());
        assert_eq!(r.verdict, ScanVerdict::Malicious);
        assert_eq!(r.reasons[0].code, "blocklist");
        assert_eq!(r.reasons[0].detail, "nn-lab-test-elf");
    }

    #[test]
    fn an_allowed_packed_file_is_trusted_and_its_findings_kept() {
        let body = [b"UPX!".to_vec(), noise(16384, 5)].concat();
        let total = (0x100 + body.len()) as u64;
        let phs = [Ph {
            kind: PT_LOAD,
            flags: PF_R | PF_W | PF_X,
            offset: 0,
            vaddr: 0x40_0000,
            filesz: total,
            memsz: total,
        }];
        let img = elf64(ET_EXEC, 0x40_0100, &phs, 0x100, &body, &[]);
        let plain = Engine::new(&ScanConfig::default()).scan(img.as_slice(), &req());
        assert_eq!(plain.verdict, ScanVerdict::Suspicious);
        let allowed = Engine::new(&ScanConfig {
            allow: vec![HashEntry {
                sha256: sha(&img),
                label: "vendor-packed".into(),
            }],
            ..ScanConfig::default()
        })
        .scan(img.as_slice(), &req());
        assert_eq!(allowed.verdict, ScanVerdict::Trusted);
        assert!(allowed.reasons.iter().any(|r| r.code == "elf.upx_marker"));
        // a higher threshold lets the same file through
        let lax = Engine::new(&ScanConfig {
            suspicious_threshold: 100,
            ..ScanConfig::default()
        })
        .scan(img.as_slice(), &req());
        assert_eq!(lax.verdict, ScanVerdict::Clean);
    }

    #[test]
    fn a_file_over_the_hash_limit_is_unscanned() {
        let data = vec![0u8; 5000];
        let e = Engine::new(&ScanConfig {
            max_hash_bytes: 4096,
            ..ScanConfig::default()
        });
        let r = e.scan(data.as_slice(), &req());
        assert_eq!(r.verdict, ScanVerdict::Unscanned);
        assert_eq!(r.reasons[0].code, "too_large");
    }

    #[test]
    fn hello_reports_lists_and_yara() {
        let e = Engine::new(&ScanConfig {
            yara_rules: Some(vec![0; 10]),
            ..ScanConfig::default()
        });
        let h = e.hello(997, true);
        assert!(h.yara.starts_with("not built (10 bytes"), "{}", h.yara);
        assert_eq!(h.block_entries, 0);
        assert!(h.seccomp);
        assert_eq!(
            Engine::new(&ScanConfig::default()).hello(1, true).yara,
            "none"
        );
    }
}
