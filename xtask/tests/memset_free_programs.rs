//! Lot 1.4 (plan S1; lot 1.2's verifier report): the `finit_module` judge
//! (`module_read_file_observe`, LSM `kernel_read_file`) calls no `memset`.
//!
//! A call of the `memset` subprogram is one the 5.15 and 6.1 verifiers
//! cross without their precision marks (KERNEL_COMPATIBILITY "Older
//! verifiers", rule 9): states stop merging past it. With LLVM 22 the
//! zeroed key of `open_sensor::key_of` (inlined five times into the judge)
//! became two such calls, and the program processed 11 % more
//! instructions on 5.15 and 6.1. The key's words now start from a value the
//! compiler cannot fold into a `memset`. Here the built object is read: the
//! program's section has no relocation to `memset`. Without the object
//! (no eBPF build) the test is skipped, unless `NN_REQUIRE_EBPF_OBJECT` is
//! set (the gates and CI's eBPF job).

mod support;

use std::fs;

use support::repo_root;

/// The programs' sections that must call no `memset`.
const MEMSET_FREE: &[&str] = &["lsm/kernel_read_file"];

fn u16_at(b: &[u8], at: usize) -> usize {
    u16::from_le_bytes([b[at], b[at + 1]]) as usize
}

fn u32_at(b: &[u8], at: usize) -> usize {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize
}

fn u64_at(b: &[u8], at: usize) -> usize {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap()) as usize
}

fn c_str(b: &[u8], at: usize) -> String {
    let end = b[at..]
        .iter()
        .position(|c| *c == 0)
        .map_or(b.len(), |n| at + n);
    String::from_utf8_lossy(&b[at..end]).into_owned()
}

/// Section header `i`: (name, type, offset, size, link, info).
fn section(b: &[u8], i: usize) -> (String, u32, usize, usize, usize, usize) {
    let shoff = u64_at(b, 0x28);
    let shentsize = u16_at(b, 0x3A);
    let shstrndx = u16_at(b, 0x3E);
    let h = shoff + i * shentsize;
    let names = shoff + shstrndx * shentsize;
    let name = c_str(b, u64_at(b, names + 0x18) + u32_at(b, h));
    (
        name,
        u32_at(b, h + 4) as u32,
        u64_at(b, h + 0x18),
        u64_at(b, h + 0x20),
        u32_at(b, h + 0x28),
        u32_at(b, h + 0x2C),
    )
}

/// Every relocation of the ELF object `b`: (the section it applies to, the
/// symbol's name).
fn relocations(b: &[u8]) -> Vec<(String, String)> {
    assert_eq!(&b[..4], b"\x7fELF", "an ELF object");
    assert_eq!((b[4], b[5]), (2, 1), "ELF64, little-endian");
    let shnum = u16_at(b, 0x3C);
    let mut out = Vec::new();
    for i in 0..shnum {
        let (_, ty, off, size, link, info) = section(b, i);
        // SHT_REL: r_offset, r_info (the symbol's index in the high half)
        if ty != 9 {
            continue;
        }
        let target = section(b, info).0;
        let (_, _, symoff, _, strndx, _) = section(b, link);
        let stroff = section(b, strndx).2;
        for e in (off..off + size).step_by(16) {
            let sym = u64_at(b, e + 8) >> 32;
            let name = c_str(b, stroff + u32_at(b, symoff + sym * 24));
            out.push((target.clone(), name));
        }
    }
    out
}

#[test]
fn the_module_judge_calls_no_memset() {
    let path =
        repo_root().join("agent-ebpf/target/bpfel-unknown-none/release/northnarrow-agent-ebpf");
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            assert!(
                std::env::var_os("NN_REQUIRE_EBPF_OBJECT").is_none(),
                "NN_REQUIRE_EBPF_OBJECT is set and {} cannot be read: {e}",
                path.display()
            );
            eprintln!("skipped: no eBPF object at {} ({e})", path.display());
            return;
        }
    };
    let rel = relocations(&bytes);
    // the reader sees the object's calls: the memset subprogram is called
    // somewhere (the other programs' zeroed arrays)
    assert!(
        rel.iter().any(|(_, s)| s == "memset"),
        "no memset relocation at all: the reader is wrong"
    );
    for sec in MEMSET_FREE {
        assert!(
            rel.iter().any(|(t, _)| t == sec),
            "{sec}: no relocation read (no such section?)"
        );
        let n = rel
            .iter()
            .filter(|(t, s)| t == sec && s == "memset")
            .count();
        assert_eq!(
            n, 0,
            "{sec} calls memset {n} times (KERNEL_COMPATIBILITY rule 9)"
        );
    }
}
