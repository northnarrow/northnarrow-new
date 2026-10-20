//! External audit EBPF-022: the eBPF object must carry a `.BTF` section.
//!
//! bpf-linker emits it from the debug info (`debug = 2` in the eBPF
//! profiles and `-C debuginfo=2 -C link-arg=--btf` in
//! `agent-ebpf/.cargo/config.toml`). Without it every LSM program fails to
//! load and the agent refuses to start on the host, which is loud but
//! late: `cargo xtask build-ebpf` refuses the object at build time instead.
//!
//! The check reads the ELF64 section headers only (no dependency, no
//! parse of the BTF itself): a section named `.BTF` with a non-zero size.

use anyhow::{bail, Result};

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// `(name, size)` of every section of a little-endian ELF64 object, or
/// `None` when the headers are not one.
fn sections(elf: &[u8]) -> Option<Vec<(String, u64)>> {
    if elf.get(..4)? != b"\x7fELF" || *elf.get(4)? != 2 || *elf.get(5)? != 1 {
        return None;
    }
    let shoff = usize::try_from(u64_at(elf, 0x28)?).ok()?;
    let shentsize = usize::from(u16_at(elf, 0x3a)?);
    let shnum = usize::from(u16_at(elf, 0x3c)?);
    let shstrndx = usize::from(u16_at(elf, 0x3e)?);
    if shentsize < 0x40 || shstrndx >= shnum {
        return None;
    }
    let header = |i: usize| shoff.checked_add(i.checked_mul(shentsize)?);
    let strtab = header(shstrndx)?;
    let str_off = usize::try_from(u64_at(elf, strtab + 0x18)?).ok()?;
    let str_size = usize::try_from(u64_at(elf, strtab + 0x20)?).ok()?;
    let names = elf.get(str_off..str_off.checked_add(str_size)?)?;
    (0..shnum)
        .map(|i| {
            let h = header(i)?;
            let name_at = usize::try_from(u32_at(elf, h)?).ok()?;
            let rest = names.get(name_at..)?;
            let end = rest.iter().position(|&c| c == 0)?;
            let name = String::from_utf8_lossy(&rest[..end]).into_owned();
            Some((name, u64_at(elf, h + 0x20)?))
        })
        .collect()
}

/// `Ok` when `elf` is an ELF64 object with a non-empty `.BTF` section.
pub fn require_btf(elf: &[u8]) -> Result<()> {
    let Some(sections) = sections(elf) else {
        bail!("the eBPF object is not a little-endian ELF64 file with readable section headers");
    };
    match sections.iter().find(|(n, _)| n == ".BTF") {
        Some((_, size)) if *size > 0 => Ok(()),
        Some(_) => bail!("the eBPF object's .BTF section is empty"),
        None => bail!(
            "the eBPF object has no .BTF section: the LSM programs cannot load without it \
             (bpf-linker needs `debug = 2` in agent-ebpf/Cargo.toml and `-C debuginfo=2 \
             -C link-arg=--btf` in agent-ebpf/.cargo/config.toml)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal little-endian ELF64 object whose sections are `names`
    /// (each 4 bytes of content), the section-name table last.
    fn elf_with(names: &[&str]) -> Vec<u8> {
        let mut strtab = vec![0u8];
        let mut name_off = Vec::new();
        for n in names.iter().chain(std::iter::once(&".shstrtab")) {
            name_off.push(strtab.len() as u32);
            strtab.extend_from_slice(n.as_bytes());
            strtab.push(0);
        }
        let mut out = vec![0u8; 0x40];
        out[..4].copy_from_slice(b"\x7fELF");
        out[4] = 2; // ELFCLASS64
        out[5] = 1; // little-endian
        out[6] = 1;
        let mut data_off = Vec::new();
        for _ in names {
            data_off.push(out.len() as u64);
            out.extend_from_slice(&[1, 2, 3, 4]);
        }
        let str_off = out.len() as u64;
        out.extend_from_slice(&strtab);
        while !out.len().is_multiple_of(8) {
            out.push(0);
        }
        let shoff = out.len() as u64;
        let shnum = names.len() + 2; // the null section, then the names
        let push_header = |out: &mut Vec<u8>, name: u32, off: u64, size: u64| {
            let mut h = [0u8; 0x40];
            h[..4].copy_from_slice(&name.to_le_bytes());
            h[4..8].copy_from_slice(&1u32.to_le_bytes());
            h[0x18..0x20].copy_from_slice(&off.to_le_bytes());
            h[0x20..0x28].copy_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&h);
        };
        out.extend_from_slice(&[0u8; 0x40]);
        for (i, off) in data_off.iter().enumerate() {
            push_header(&mut out, name_off[i], *off, 4);
        }
        push_header(
            &mut out,
            name_off[names.len()],
            str_off,
            strtab.len() as u64,
        );
        out[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
        out[0x3a..0x3c].copy_from_slice(&0x40u16.to_le_bytes());
        out[0x3c..0x3e].copy_from_slice(&(shnum as u16).to_le_bytes());
        out[0x3e..0x40].copy_from_slice(&((shnum - 1) as u16).to_le_bytes());
        out
    }

    /// External audit EBPF-022: an object without `.BTF` is refused at
    /// build time, not at the agent's start on a host.
    #[test]
    fn build_refuses_object_without_btf() {
        assert!(require_btf(&elf_with(&["tracepoint", "license", ".BTF", ".BTF.ext"])).is_ok());
        let e = require_btf(&elf_with(&["tracepoint", "license", ".BTF.ext"])).unwrap_err();
        assert!(e.to_string().contains("no .BTF section"), "{e}");
        assert!(require_btf(b"not an elf").is_err());
        let mut cut = elf_with(&[".BTF"]);
        cut.truncate(0x50);
        assert!(require_btf(&cut).is_err(), "headers past the end");
    }

    /// The object `cargo xtask build-ebpf --release` produced, when there
    /// is one: it carries `.BTF`.
    #[test]
    fn the_built_object_carries_btf() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../agent-ebpf/target/bpfel-unknown-none/release/northnarrow-agent-ebpf");
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("skipped: no eBPF object at {}", path.display());
            return;
        };
        require_btf(&bytes).unwrap();
    }
}
