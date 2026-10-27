//! Explainable format heuristics (lab PR 223).
//!
//! Each finding is a [`Reason`]: a stable code, what was seen, and a weight.
//! The scanner calls a file suspicious when the weights reach the
//! configured threshold (3 by default), so no single weak sign — a static
//! stripped binary, a Go program — makes a verdict alone, and every verdict
//! can be read back from its reasons. The weights:
//!
//! | code | weight | what |
//! |---|---|---|
//! | `elf.upx_marker` | 3 | the UPX packer's `UPX!` header or banner |
//! | `elf.unusual_interpreter` | 3 | `PT_INTERP` outside the system library directories |
//! | `script.unusual_interpreter` | 3 | a `#!` interpreter in a writable location, or relative |
//! | `elf.packed_no_sections` | 2 | no section table and an executable segment of entropy ≥ 7.2 |
//! | `elf.high_entropy_code` | 2 | an executable section of entropy ≥ 7.2 |
//! | `elf.rwx_segment` | 2 | a `PT_LOAD` segment readable, writable and executable |
//! | `elf.entry_outside_code` | 2 | the entry point in no executable segment |
//! | `elf.needed_without_interpreter` | 2 | `DT_NEEDED` libraries and no `PT_INTERP` to load them |
//! | `elf.malformed` | 2 | header tables past the end of the file |
//! | `elf.suspicious_imports` | 2 (≤ 256 KiB) / 1 | `ptrace`, `memfd_create`, `process_vm_writev`… |
//! | `elf.static_stripped` | 2 (staging class) / 1 | no interpreter, no dynamic section, no symbol table |

use common::wire::execq::class;
use nn_proto::execq::Reason;

use crate::elf::{
    Elf, ElfError, ET_DYN, ET_EXEC, PF_R, PF_W, PF_X, PT_DYNAMIC, PT_INTERP, PT_LOAD,
    SHF_EXECINSTR, SHT_NOBITS, SHT_SYMTAB,
};

/// Bits per byte from which content looks compressed or encrypted.
pub const HIGH_ENTROPY: f64 = 7.2;
/// Smallest region whose entropy is judged (a short one says nothing).
pub const MIN_ENTROPY_BYTES: usize = 4096;
/// Size under which suspicious imports weigh more: a small program built
/// around them rather than a large one that also links them.
pub const SMALL_BINARY: u64 = 256 * 1024;

/// Imports worth naming in a program run from a writable location: process
/// injection, fileless execution, kernel and namespace manipulation.
pub const SUSPICIOUS_IMPORTS: &[&str] = &[
    "ptrace",
    "memfd_create",
    "process_vm_writev",
    "process_vm_readv",
    "fexecve",
    "execveat",
    "init_module",
    "finit_module",
    "delete_module",
    "setns",
    "unshare",
    "pivot_root",
    "bpf",
    "keyctl",
];

/// Interpreter directories a distribution's loader lives in.
const SYSTEM_INTERP_DIRS: &[&str] = &[
    "/lib/",
    "/lib64/",
    "/lib32/",
    "/libx32/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/lib32/",
    "/usr/libx32/",
];

/// Script interpreters' standard homes.
const SYSTEM_SCRIPT_DIRS: &[&str] = &["/bin/", "/sbin/", "/usr/", "/opt/", "/snap/", "/nix/store/"];

/// What the heuristics make of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Findings {
    /// `elf64-x86_64-dyn`, `script:/bin/sh`, `data`.
    pub format: String,
    pub reasons: Vec<Reason>,
}

impl Findings {
    pub fn score(&self) -> u32 {
        self.reasons.iter().map(|r| r.weight).sum()
    }
}

/// Shannon entropy of `b`, bits per byte.
pub fn entropy(b: &[u8]) -> f64 {
    if b.is_empty() {
        return 0.0;
    }
    let mut hist = [0u64; 256];
    for &x in b {
        hist[x as usize] += 1;
    }
    let n = b.len() as f64;
    hist.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Assess `data`, the first bytes of a file of `file_size` bytes (all of it
/// when `data.len() == file_size`), executed from the [`class`] bits
/// `class_bits`.
pub fn assess(data: &[u8], file_size: u64, class_bits: u32) -> Findings {
    if data.starts_with(b"#!") {
        return assess_script(data);
    }
    match Elf::parse(data) {
        Ok(elf) => assess_elf(&elf, file_size, class_bits),
        Err(ElfError::NotElf) => Findings {
            format: "data".to_string(),
            reasons: Vec::new(),
        },
        Err(ElfError::Truncated) => Findings {
            format: "elf-truncated".to_string(),
            reasons: vec![Reason::new("elf.malformed", "the ELF header is cut", 2)],
        },
        Err(ElfError::Unsupported(why)) => Findings {
            format: format!("elf-{}", why.replace(' ', "-")),
            reasons: vec![Reason::new("elf.not_examined", why, 0)],
        },
    }
}

fn assess_script(data: &[u8]) -> Findings {
    let line_end = data
        .iter()
        .take(256)
        .position(|&b| b == b'\n')
        .unwrap_or(data.len().min(256));
    let line = String::from_utf8_lossy(&data[2..line_end]);
    let interp = line.split_whitespace().next().unwrap_or("").to_string();
    let mut reasons = Vec::new();
    let standard = SYSTEM_SCRIPT_DIRS.iter().any(|d| interp.starts_with(d));
    if !interp.is_empty() && !standard {
        reasons.push(Reason::new(
            "script.unusual_interpreter",
            format!("#! interpreter `{interp}` outside the system directories"),
            3,
        ));
    }
    Findings {
        format: format!("script:{interp}"),
        reasons,
    }
}

fn assess_elf(elf: &Elf<'_>, file_size: u64, class_bits: u32) -> Findings {
    let data = elf.data();
    let complete = data.len() as u64 >= file_size;
    let mut reasons = Vec::new();
    let segments = elf.segments();
    let sections = elf.sections();

    // UPX: its l_info header (`UPX!`) right after the program headers and
    // its pack header near the end; the banner in between.
    let head = &data[..data.len().min(64 * 1024)];
    let tail = if complete {
        &data[data.len().saturating_sub(4096)..]
    } else {
        &[][..]
    };
    if let Some(at) = find(head, b"UPX!") {
        reasons.push(Reason::new(
            "elf.upx_marker",
            format!("UPX! header at offset {at:#x}"),
            3,
        ));
    } else if find(head, b"This file is packed with the UPX").is_some()
        || find(tail, b"UPX!").is_some()
    {
        reasons.push(Reason::new(
            "elf.upx_marker",
            "UPX packer banner or pack header",
            3,
        ));
    }

    // Header tables past the end of the file.
    if elf.program_headers_end() > file_size
        || (elf.shnum > 0 && elf.section_headers_end() > file_size)
    {
        reasons.push(Reason::new(
            "elf.malformed",
            format!(
                "header tables end at {:#x} / {:#x}, the file has {file_size} bytes",
                elf.program_headers_end(),
                elf.section_headers_end()
            ),
            2,
        ));
    }

    let exec_loads: Vec<_> = segments
        .iter()
        .filter(|s| s.kind == PT_LOAD && s.flags & PF_X != 0)
        .collect();
    if let Some(s) = segments
        .iter()
        .find(|s| s.kind == PT_LOAD && s.flags & (PF_R | PF_W | PF_X) == PF_R | PF_W | PF_X)
    {
        reasons.push(Reason::new(
            "elf.rwx_segment",
            format!("PT_LOAD at {:#x} ({} bytes) is RWX", s.vaddr, s.memsz),
            2,
        ));
    }

    if sections.is_empty() {
        // No section table (sstrip, a packer): judge the code segments.
        let hot = exec_loads.iter().find_map(|s| {
            let b = elf.bytes(s.offset, s.filesz)?;
            let e = entropy(b);
            (b.len() >= MIN_ENTROPY_BYTES && e >= HIGH_ENTROPY).then_some((b.len(), e))
        });
        if let Some((n, e)) = hot {
            reasons.push(Reason::new(
                "elf.packed_no_sections",
                format!("no section table; executable segment of {n} bytes, entropy {e:.2}"),
                2,
            ));
        }
    } else {
        let hot: Vec<String> = sections
            .iter()
            .filter(|s| s.flags & SHF_EXECINSTR != 0 && s.kind != SHT_NOBITS)
            .filter_map(|s| {
                let b = elf.bytes(s.offset, s.size)?;
                let e = entropy(b);
                (b.len() >= MIN_ENTROPY_BYTES && e >= HIGH_ENTROPY).then(|| {
                    let name = elf.section_name(&sections, s).unwrap_or("?");
                    format!("{name} ({} bytes, entropy {e:.2})", b.len())
                })
            })
            .collect();
        if !hot.is_empty() {
            reasons.push(Reason::new("elf.high_entropy_code", hot.join(", "), 2));
        }
    }

    let runnable = elf.e_type == ET_EXEC || elf.e_type == ET_DYN;
    if runnable && elf.entry != 0 && !exec_loads.is_empty() {
        let inside = exec_loads
            .iter()
            .any(|s| elf.entry >= s.vaddr && elf.entry - s.vaddr < s.memsz.max(s.filesz));
        if !inside {
            reasons.push(Reason::new(
                "elf.entry_outside_code",
                format!("entry point {:#x} is in no executable segment", elf.entry),
                2,
            ));
        }
    }

    let has_interp = segments.iter().any(|s| s.kind == PT_INTERP);
    let has_dynamic = segments.iter().any(|s| s.kind == PT_DYNAMIC);
    if let Some(interp) = elf.interp() {
        if !SYSTEM_INTERP_DIRS.iter().any(|d| interp.starts_with(d)) {
            reasons.push(Reason::new(
                "elf.unusual_interpreter",
                format!("PT_INTERP `{interp}` outside the system library directories"),
                3,
            ));
        }
    }
    if runnable && has_dynamic && !has_interp {
        let needed = elf
            .dynamic()
            .iter()
            .filter(|(t, _)| *t == crate::elf::DT_NEEDED)
            .count();
        if needed > 0 {
            reasons.push(Reason::new(
                "elf.needed_without_interpreter",
                format!("{needed} DT_NEEDED libraries and no PT_INTERP to load them"),
                2,
            ));
        }
    }
    if runnable && !has_interp && !has_dynamic && !sections.iter().any(|s| s.kind == SHT_SYMTAB) {
        let staging =
            class::TMP | class::TMPFS | class::WORLD_WRITABLE_DIR | class::MEMFD | class::DELETED;
        let weight = if class_bits & staging != 0 { 2 } else { 1 };
        reasons.push(Reason::new(
            "elf.static_stripped",
            "static binary without a symbol table",
            weight,
        ));
    }

    let mut imports: Vec<&str> = elf
        .dynamic_strings()
        .into_iter()
        .filter(|s| SUSPICIOUS_IMPORTS.contains(s))
        .collect();
    imports.sort_unstable();
    imports.dedup();
    if !imports.is_empty() {
        let weight = if file_size <= SMALL_BINARY { 2 } else { 1 };
        reasons.push(Reason::new(
            "elf.suspicious_imports",
            format!("{} (file of {file_size} bytes)", imports.join(", ")),
            weight,
        ));
    }

    Findings {
        format: elf.describe(),
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::fixtures::*;
    use crate::elf::{DT_NEEDED, DT_NULL, DT_STRSZ, DT_STRTAB};

    fn codes(f: &Findings) -> Vec<&str> {
        f.reasons.iter().map(|r| r.code.as_str()).collect()
    }

    /// A conventional dynamic executable: interpreter, dynamic section,
    /// `.text` of ordinary entropy, `.symtab`.
    fn ordinary(dynstr: &[u8]) -> Vec<u8> {
        let interp = b"/lib64/ld-linux-x86-64.so.2\0";
        let body_off = 0x200usize;
        let mut body = interp.to_vec();
        body.resize(0x80, 0);
        let dynstr_off = (body_off + body.len()) as u64;
        body.extend_from_slice(dynstr);
        while !body.len().is_multiple_of(8) {
            body.push(0);
        }
        let dyn_off = (body_off + body.len()) as u64;
        for (t, v) in [
            (DT_NEEDED, 1u64),
            (DT_STRTAB, 0x40_0000 + dynstr_off),
            (DT_STRSZ, dynstr.len() as u64),
            (DT_NULL, 0),
        ] {
            body.extend_from_slice(&t.to_le_bytes());
            body.extend_from_slice(&v.to_le_bytes());
        }
        let text_off = (body_off + body.len()) as u64;
        body.extend_from_slice(&code(8192));
        let total = (body_off + body.len()) as u64;
        let phs = [
            Ph {
                kind: PT_INTERP,
                flags: PF_R,
                offset: body_off as u64,
                vaddr: 0x40_0000 + body_off as u64,
                filesz: interp.len() as u64,
                memsz: interp.len() as u64,
            },
            Ph {
                kind: PT_LOAD,
                flags: PF_R | PF_X,
                offset: 0,
                vaddr: 0x40_0000,
                filesz: total,
                memsz: total,
            },
            Ph {
                kind: PT_DYNAMIC,
                flags: PF_R | PF_W,
                offset: dyn_off,
                vaddr: 0x40_0000 + dyn_off,
                filesz: 64,
                memsz: 64,
            },
        ];
        let shs = [Sh {
            name: ".symtab",
            kind: SHT_SYMTAB,
            flags: 0,
            content: vec![0; 24],
            link: 0,
        }];
        let mut img = elf64(ET_DYN, 0x40_0000 + text_off, &phs, body_off, &body, &shs);
        // the .text section header is not needed for the checks above; a
        // section table exists (the .symtab one), so the per-section
        // entropy check applies and finds nothing executable.
        img.shrink_to_fit();
        img
    }

    #[test]
    fn an_ordinary_dynamic_binary_is_clean() {
        let img = ordinary(b"\0libc.so.6\0puts\0exit\0");
        let f = assess(&img, img.len() as u64, class::HOME);
        assert_eq!(f.format, "elf64-x86_64-dyn");
        assert!(f.reasons.is_empty(), "{:?}", f.reasons);
        assert_eq!(f.score(), 0);
    }

    #[test]
    fn suspicious_imports_are_named_and_weigh_more_in_a_small_binary() {
        let img = ordinary(b"\0libc.so.6\0ptrace\0memfd_create\0puts\0");
        let f = assess(&img, img.len() as u64, class::HOME);
        let r = f
            .reasons
            .iter()
            .find(|r| r.code == "elf.suspicious_imports")
            .unwrap();
        assert_eq!(r.weight, 2);
        assert!(r.detail.starts_with("memfd_create, ptrace"), "{}", r.detail);
        let big = assess(&img, 10 << 20, class::HOME);
        let r = big
            .reasons
            .iter()
            .find(|r| r.code == "elf.suspicious_imports")
            .unwrap();
        assert_eq!(r.weight, 1);
    }

    /// A UPX-like image: no section table, one RWX segment of packed
    /// (high-entropy) bytes, the `UPX!` header after the program headers.
    #[test]
    fn a_packed_binary_is_suspicious_on_explainable_reasons() {
        let body_off = 0x100usize;
        let mut body = b"UPX!\x0d\x0c\x08\x08".to_vec();
        body.extend_from_slice(&noise(32 * 1024, 7));
        let total = (body_off + body.len()) as u64;
        let phs = [Ph {
            kind: PT_LOAD,
            flags: PF_R | PF_W | PF_X,
            offset: 0,
            vaddr: 0x40_0000,
            filesz: total,
            memsz: total * 3,
        }];
        let img = elf64(ET_EXEC, 0x40_0000 + 0x400, &phs, body_off, &body, &[]);
        let f = assess(&img, img.len() as u64, class::TMP);
        let c = codes(&f);
        for want in [
            "elf.upx_marker",
            "elf.rwx_segment",
            "elf.packed_no_sections",
            "elf.static_stripped",
        ] {
            assert!(c.contains(&want), "{want} missing from {c:?}");
        }
        assert!(f.score() >= 3);
        let upx = f
            .reasons
            .iter()
            .find(|r| r.code == "elf.upx_marker")
            .unwrap();
        assert_eq!(upx.detail, "UPX! header at offset 0x100");
    }

    #[test]
    fn a_static_stripped_binary_alone_stays_below_the_threshold() {
        let body_off = 0x100usize;
        let body = code(16 * 1024);
        let total = (body_off + body.len()) as u64;
        let phs = [Ph {
            kind: PT_LOAD,
            flags: PF_R | PF_X,
            offset: 0,
            vaddr: 0x40_0000,
            filesz: total,
            memsz: total,
        }];
        let img = elf64(ET_EXEC, 0x40_0100, &phs, body_off, &body, &[]);
        let home = assess(&img, img.len() as u64, class::HOME);
        assert_eq!(codes(&home), ["elf.static_stripped"]);
        assert_eq!(home.score(), 1);
        let tmp = assess(&img, img.len() as u64, class::TMP);
        assert_eq!(
            tmp.score(),
            2,
            "stronger from a staging directory, still < 3"
        );
    }

    #[test]
    fn interpreter_entry_and_table_oddities_are_reported() {
        let interp = b"/tmp/.x/ld.so\0";
        let body_off = 0x100usize;
        let mut body = interp.to_vec();
        body.extend_from_slice(&code(4096));
        let total = (body_off + body.len()) as u64;
        let phs = [
            Ph {
                kind: PT_INTERP,
                flags: PF_R,
                offset: body_off as u64,
                vaddr: 0,
                filesz: interp.len() as u64,
                memsz: 0,
            },
            Ph {
                kind: PT_LOAD,
                flags: PF_R | PF_X,
                offset: 0,
                vaddr: 0x40_0000,
                filesz: total,
                memsz: total,
            },
        ];
        let mut img = elf64(ET_EXEC, 0x90_0000, &phs, body_off, &body, &[]);
        // a section table declared past the end of the file
        img[40..48].copy_from_slice(&(1u64 << 20).to_le_bytes());
        img[58..60].copy_from_slice(&64u16.to_le_bytes());
        img[60..62].copy_from_slice(&3u16.to_le_bytes());
        let f = assess(&img, img.len() as u64, class::HOME);
        let c = codes(&f);
        for want in [
            "elf.unusual_interpreter",
            "elf.entry_outside_code",
            "elf.malformed",
        ] {
            assert!(c.contains(&want), "{want} missing from {c:?}");
        }
    }

    #[test]
    fn scripts_and_other_formats() {
        let f = assess(b"#!/bin/sh\necho hi\n", 18, class::TMP);
        assert_eq!(f.format, "script:/bin/sh");
        assert!(f.reasons.is_empty());
        let f = assess(b"#!/tmp/x -e\n", 12, class::TMP);
        assert_eq!(codes(&f), ["script.unusual_interpreter"]);
        assert_eq!(assess(b"hello", 5, 0).format, "data");
        assert_eq!(codes(&assess(b"\x7fELF\x02", 5, 0)), ["elf.malformed"]);
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[7; 100]), 0.0);
        assert!(entropy(&noise(1 << 16, 3)) > 7.9);
        assert!(
            entropy(&code(1 << 16)) < HIGH_ENTROPY - 0.3,
            "ordinary code stays clear of the threshold"
        );
    }
}
