//! A bounded, read-only ELF reader for the heuristics (lab PR 223).
//!
//! Hand-written rather than a general ELF crate: it reads what the
//! heuristics name and nothing else, every offset is checked against the
//! bytes it was given (a hostile header can only make it report less), it
//! allocates at most one entry per header the file declares, capped, and
//! it never follows a pointer twice. ELF32 and ELF64, little-endian only
//! (a big-endian file is reported as such, not parsed further).

/// `e_type`.
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const ET_CORE: u16 = 4;
/// `p_type`.
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
/// `p_flags`.
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;
/// `sh_type`.
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_DYNSYM: u32 = 11;
/// `sh_flags`.
pub const SHF_EXECINSTR: u64 = 4;
/// `d_tag`.
pub const DT_NULL: u64 = 0;
pub const DT_NEEDED: u64 = 1;
pub const DT_STRTAB: u64 = 5;
pub const DT_STRSZ: u64 = 10;

/// Headers of each kind read at most (a real binary has tens).
pub const MAX_HEADERS: usize = 4096;
/// Dynamic entries read at most.
const MAX_DYN: usize = 4096;
/// Bytes of a string table read at most.
const MAX_STRTAB: u64 = 4 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    /// No ELF magic.
    NotElf,
    /// The ELF header itself is cut.
    Truncated,
    /// Big-endian or an unknown class: not parsed further.
    Unsupported(&'static str),
}

/// One program header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub kind: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
}

/// One section header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    pub name_off: u32,
    pub kind: u32,
    pub flags: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
}

/// A parsed ELF header over `data` (a file's first bytes, maybe not all).
#[derive(Debug, Clone)]
pub struct Elf<'a> {
    data: &'a [u8],
    pub is64: bool,
    pub e_type: u16,
    pub machine: u16,
    pub entry: u64,
    phoff: u64,
    phentsize: u64,
    pub phnum: u16,
    shoff: u64,
    shentsize: u64,
    pub shnum: u16,
    shstrndx: u16,
}

fn u16_at(d: &[u8], off: u64) -> Option<u16> {
    let o = usize::try_from(off).ok()?;
    Some(u16::from_le_bytes(
        d.get(o..o.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn u32_at(d: &[u8], off: u64) -> Option<u32> {
    let o = usize::try_from(off).ok()?;
    Some(u32::from_le_bytes(
        d.get(o..o.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn u64_at(d: &[u8], off: u64) -> Option<u64> {
    let o = usize::try_from(off).ok()?;
    Some(u64::from_le_bytes(
        d.get(o..o.checked_add(8)?)?.try_into().ok()?,
    ))
}

impl<'a> Elf<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ElfError> {
        if data.len() < 4 || &data[..4] != b"\x7fELF" {
            return Err(ElfError::NotElf);
        }
        if data.len() < 6 {
            return Err(ElfError::Truncated);
        }
        let is64 = match data[4] {
            1 => false,
            2 => true,
            _ => return Err(ElfError::Unsupported("unknown ELF class")),
        };
        if data[5] != 1 {
            return Err(ElfError::Unsupported("big-endian"));
        }
        let t = ElfError::Truncated;
        let e_type = u16_at(data, 16).ok_or(t)?;
        let machine = u16_at(data, 18).ok_or(t)?;
        let e = if is64 {
            Elf {
                data,
                is64,
                e_type,
                machine,
                entry: u64_at(data, 24).ok_or(t)?,
                phoff: u64_at(data, 32).ok_or(t)?,
                shoff: u64_at(data, 40).ok_or(t)?,
                phentsize: u64::from(u16_at(data, 54).ok_or(t)?),
                phnum: u16_at(data, 56).ok_or(t)?,
                shentsize: u64::from(u16_at(data, 58).ok_or(t)?),
                shnum: u16_at(data, 60).ok_or(t)?,
                shstrndx: u16_at(data, 62).ok_or(t)?,
            }
        } else {
            Elf {
                data,
                is64,
                e_type,
                machine,
                entry: u64::from(u32_at(data, 24).ok_or(t)?),
                phoff: u64::from(u32_at(data, 28).ok_or(t)?),
                shoff: u64::from(u32_at(data, 32).ok_or(t)?),
                phentsize: u64::from(u16_at(data, 42).ok_or(t)?),
                phnum: u16_at(data, 44).ok_or(t)?,
                shentsize: u64::from(u16_at(data, 46).ok_or(t)?),
                shnum: u16_at(data, 48).ok_or(t)?,
                shstrndx: u16_at(data, 50).ok_or(t)?,
            }
        };
        Ok(e)
    }

    /// The bytes this reader was given.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// `elf64-x86_64-dyn` and the like.
    pub fn describe(&self) -> String {
        let machine = match self.machine {
            3 => "x86".to_string(),
            40 => "arm".to_string(),
            62 => "x86_64".to_string(),
            183 => "aarch64".to_string(),
            243 => "riscv".to_string(),
            m => format!("m{m}"),
        };
        let kind = match self.e_type {
            ET_REL => "rel",
            ET_EXEC => "exec",
            ET_DYN => "dyn",
            ET_CORE => "core",
            _ => "other",
        };
        format!("elf{}-{machine}-{kind}", if self.is64 { 64 } else { 32 })
    }

    /// Where the program header table ends (it may lie past `data`).
    pub fn program_headers_end(&self) -> u64 {
        self.phoff
            .saturating_add(self.phentsize.saturating_mul(u64::from(self.phnum)))
    }

    /// Where the section header table ends.
    pub fn section_headers_end(&self) -> u64 {
        self.shoff
            .saturating_add(self.shentsize.saturating_mul(u64::from(self.shnum)))
    }

    /// The program headers within `data` (fewer than `phnum` when the
    /// table is cut or oversized).
    pub fn segments(&self) -> Vec<Segment> {
        let want = if self.is64 { 56 } else { 32 };
        if self.phentsize < want {
            return Vec::new();
        }
        let d = self.data;
        let mut v = Vec::new();
        for i in 0..usize::from(self.phnum).min(MAX_HEADERS) {
            let Some(b) = self
                .phentsize
                .checked_mul(i as u64)
                .and_then(|o| o.checked_add(self.phoff))
            else {
                break;
            };
            let seg = if self.is64 {
                segment64(d, b)
            } else {
                segment32(d, b)
            };
            match seg {
                Some(s) => v.push(s),
                None => break,
            }
        }
        v
    }

    /// The section headers within `data`.
    pub fn sections(&self) -> Vec<Section> {
        let want = if self.is64 { 64 } else { 40 };
        if self.shnum == 0 || self.shentsize < want {
            return Vec::new();
        }
        let d = self.data;
        let mut v = Vec::new();
        for i in 0..usize::from(self.shnum).min(MAX_HEADERS) {
            let Some(b) = self
                .shentsize
                .checked_mul(i as u64)
                .and_then(|o| o.checked_add(self.shoff))
            else {
                break;
            };
            let sec = if self.is64 {
                section64(d, b)
            } else {
                section32(d, b)
            };
            match sec {
                Some(s) => v.push(s),
                None => break,
            }
        }
        v
    }

    /// `len` bytes at `off`, when `data` holds all of them.
    pub fn bytes(&self, off: u64, len: u64) -> Option<&'a [u8]> {
        let start = usize::try_from(off).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        self.data.get(start..end)
    }

    /// A section's name from the section-name table.
    pub fn section_name(&self, sections: &[Section], s: &Section) -> Option<&'a str> {
        let names = sections.get(usize::from(self.shstrndx))?;
        cstr_at(
            self.bytes(names.offset, names.size.min(MAX_STRTAB))?,
            s.name_off,
        )
    }

    /// The `PT_INTERP` path.
    pub fn interp(&self) -> Option<&'a str> {
        let seg = self.segments().into_iter().find(|s| s.kind == PT_INTERP)?;
        let b = self.bytes(seg.offset, seg.filesz.min(4096))?;
        cstr_at(b, 0)
    }

    /// File offset of virtual address `vaddr`, through the `PT_LOAD`
    /// segment that maps it.
    fn file_offset(&self, segments: &[Segment], vaddr: u64) -> Option<u64> {
        segments
            .iter()
            .filter(|s| s.kind == PT_LOAD)
            .find(|s| vaddr >= s.vaddr && vaddr - s.vaddr < s.filesz)
            .and_then(|s| s.offset.checked_add(vaddr - s.vaddr))
    }

    /// The dynamic entries `(tag, value)` of `PT_DYNAMIC`.
    pub fn dynamic(&self) -> Vec<(u64, u64)> {
        let Some(seg) = self.segments().into_iter().find(|s| s.kind == PT_DYNAMIC) else {
            return Vec::new();
        };
        let ent = if self.is64 { 16 } else { 8 };
        let mut v = Vec::new();
        let n = usize::try_from(seg.filesz / ent).unwrap_or(0).min(MAX_DYN);
        for i in 0..n {
            let Some(b) = seg.offset.checked_add(i as u64 * ent) else {
                break;
            };
            let pair = if self.is64 {
                u64_at(self.data, b).zip(b.checked_add(8).and_then(|o| u64_at(self.data, o)))
            } else {
                u32_at(self.data, b).map(u64::from).zip(
                    b.checked_add(4)
                        .and_then(|o| u32_at(self.data, o))
                        .map(u64::from),
                )
            };
            match pair {
                Some((DT_NULL, _)) | None => break,
                Some(p) => v.push(p),
            }
        }
        v
    }

    /// The strings of the dynamic string table: imported and exported
    /// symbol names, `DT_NEEDED` libraries. From the `.dynsym` section's
    /// string table when the file has section headers, else through
    /// `DT_STRTAB` / `DT_STRSZ` (a binary stripped of its section table
    /// still has to keep these for the loader).
    pub fn dynamic_strings(&self) -> Vec<&'a str> {
        let sections = self.sections();
        let table = sections
            .iter()
            .find(|s| s.kind == SHT_DYNSYM)
            .and_then(|d| sections.get(d.link as usize))
            .and_then(|st| self.bytes(st.offset, st.size.min(MAX_STRTAB)));
        let table = table.or_else(|| {
            let dynamic = self.dynamic();
            let strtab = dynamic.iter().find(|(t, _)| *t == DT_STRTAB)?.1;
            let strsz = dynamic.iter().find(|(t, _)| *t == DT_STRSZ)?.1;
            let off = self.file_offset(&self.segments(), strtab)?;
            self.bytes(off, strsz.min(MAX_STRTAB))
        });
        match table {
            Some(t) => t
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .filter_map(|s| std::str::from_utf8(s).ok())
                .collect(),
            None => Vec::new(),
        }
    }
}

fn segment64(d: &[u8], b: u64) -> Option<Segment> {
    Some(Segment {
        kind: u32_at(d, b)?,
        flags: u32_at(d, b.checked_add(4)?)?,
        offset: u64_at(d, b.checked_add(8)?)?,
        vaddr: u64_at(d, b.checked_add(16)?)?,
        filesz: u64_at(d, b.checked_add(32)?)?,
        memsz: u64_at(d, b.checked_add(40)?)?,
    })
}

fn segment32(d: &[u8], b: u64) -> Option<Segment> {
    Some(Segment {
        kind: u32_at(d, b)?,
        offset: u64::from(u32_at(d, b.checked_add(4)?)?),
        vaddr: u64::from(u32_at(d, b.checked_add(8)?)?),
        filesz: u64::from(u32_at(d, b.checked_add(16)?)?),
        memsz: u64::from(u32_at(d, b.checked_add(20)?)?),
        flags: u32_at(d, b.checked_add(24)?)?,
    })
}

fn section64(d: &[u8], b: u64) -> Option<Section> {
    Some(Section {
        name_off: u32_at(d, b)?,
        kind: u32_at(d, b.checked_add(4)?)?,
        flags: u64_at(d, b.checked_add(8)?)?,
        offset: u64_at(d, b.checked_add(24)?)?,
        size: u64_at(d, b.checked_add(32)?)?,
        link: u32_at(d, b.checked_add(40)?)?,
    })
}

fn section32(d: &[u8], b: u64) -> Option<Section> {
    Some(Section {
        name_off: u32_at(d, b)?,
        kind: u32_at(d, b.checked_add(4)?)?,
        flags: u64::from(u32_at(d, b.checked_add(8)?)?),
        offset: u64::from(u32_at(d, b.checked_add(16)?)?),
        size: u64::from(u32_at(d, b.checked_add(20)?)?),
        link: u32_at(d, b.checked_add(24)?)?,
    })
}

/// The NUL-terminated string at `off` in `table`.
fn cstr_at(table: &[u8], off: u32) -> Option<&str> {
    let rest = table.get(off as usize..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    std::str::from_utf8(&rest[..end]).ok()
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Synthetic ELF images built byte by byte (no toolchain needed).

    /// A program header to place.
    #[derive(Clone, Copy)]
    pub struct Ph {
        pub kind: u32,
        pub flags: u32,
        pub offset: u64,
        pub vaddr: u64,
        pub filesz: u64,
        pub memsz: u64,
    }

    /// A section to place: name, type, flags, content.
    pub struct Sh<'a> {
        pub name: &'a str,
        pub kind: u32,
        pub flags: u64,
        pub content: Vec<u8>,
        pub link: u32,
    }

    /// An ELF64 little-endian x86_64 image: header, program headers at 64,
    /// then `body` at `body_off`, then (if any) the sections' contents, a
    /// `.shstrtab` and the section header table.
    pub fn elf64(
        e_type: u16,
        entry: u64,
        phs: &[Ph],
        body_off: usize,
        body: &[u8],
        shs: &[Sh],
    ) -> Vec<u8> {
        assert!(
            body_off >= 64 + 56 * phs.len(),
            "body over the program headers"
        );
        let mut f = vec![0u8; body_off];
        f[..4].copy_from_slice(b"\x7fELF");
        f[4] = 2;
        f[5] = 1;
        f[6] = 1;
        f[16..18].copy_from_slice(&e_type.to_le_bytes());
        f[18..20].copy_from_slice(&62u16.to_le_bytes());
        f[20..24].copy_from_slice(&1u32.to_le_bytes());
        f[24..32].copy_from_slice(&entry.to_le_bytes());
        f[32..40].copy_from_slice(&64u64.to_le_bytes());
        f[52..54].copy_from_slice(&64u16.to_le_bytes());
        f[54..56].copy_from_slice(&56u16.to_le_bytes());
        f[56..58].copy_from_slice(&(phs.len() as u16).to_le_bytes());
        f[58..60].copy_from_slice(&64u16.to_le_bytes());
        for (i, p) in phs.iter().enumerate() {
            let b = 64 + 56 * i;
            f[b..b + 4].copy_from_slice(&p.kind.to_le_bytes());
            f[b + 4..b + 8].copy_from_slice(&p.flags.to_le_bytes());
            f[b + 8..b + 16].copy_from_slice(&p.offset.to_le_bytes());
            f[b + 16..b + 24].copy_from_slice(&p.vaddr.to_le_bytes());
            f[b + 24..b + 32].copy_from_slice(&p.vaddr.to_le_bytes());
            f[b + 32..b + 40].copy_from_slice(&p.filesz.to_le_bytes());
            f[b + 40..b + 48].copy_from_slice(&p.memsz.to_le_bytes());
            f[b + 48..b + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        }
        f.extend_from_slice(body);
        if !shs.is_empty() {
            // contents, then .shstrtab, then the table: [null, shs…, .shstrtab]
            let mut names = vec![0u8];
            let mut placed = Vec::new();
            for s in shs {
                let name_off = names.len() as u32;
                names.extend_from_slice(s.name.as_bytes());
                names.push(0);
                let off = f.len() as u64;
                f.extend_from_slice(&s.content);
                placed.push((name_off, off, s));
            }
            let shstr_name = names.len() as u32;
            names.extend_from_slice(b".shstrtab\0");
            let shstr_off = f.len() as u64;
            f.extend_from_slice(&names);
            while !f.len().is_multiple_of(8) {
                f.push(0);
            }
            let shoff = f.len() as u64;
            f.extend_from_slice(&[0u8; 64]);
            let entry = |name: u32, kind: u32, flags: u64, off: u64, size: u64, link: u32| {
                let mut e = [0u8; 64];
                e[0..4].copy_from_slice(&name.to_le_bytes());
                e[4..8].copy_from_slice(&kind.to_le_bytes());
                e[8..16].copy_from_slice(&flags.to_le_bytes());
                e[24..32].copy_from_slice(&off.to_le_bytes());
                e[32..40].copy_from_slice(&size.to_le_bytes());
                e[40..44].copy_from_slice(&link.to_le_bytes());
                e
            };
            for (name_off, off, s) in &placed {
                f.extend_from_slice(&entry(
                    *name_off,
                    s.kind,
                    s.flags,
                    *off,
                    s.content.len() as u64,
                    s.link,
                ));
            }
            f.extend_from_slice(&entry(shstr_name, 3, 0, shstr_off, names.len() as u64, 0));
            let shnum = (shs.len() + 2) as u16;
            f[40..48].copy_from_slice(&shoff.to_le_bytes());
            f[60..62].copy_from_slice(&shnum.to_le_bytes());
            f[62..64].copy_from_slice(&(shnum - 1).to_le_bytes());
        }
        f
    }

    /// Bytes no compressor shrinks (xorshift), for high-entropy content.
    pub fn noise(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    /// Low-entropy "code": a repeating instruction-like pattern.
    pub fn code(n: usize) -> Vec<u8> {
        let pat = [
            0x55u8, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0x89, 0x7d, 0xfc, 0x90, 0xc3,
        ];
        (0..n)
            .map(|i| pat[i % pat.len()].wrapping_add((i / 97) as u8 & 7))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    #[test]
    fn not_elf_cut_and_big_endian_are_told_apart() {
        assert_eq!(Elf::parse(b"#!/bin/sh\n").unwrap_err(), ElfError::NotElf);
        assert_eq!(Elf::parse(b"\x7fELF\x02").unwrap_err(), ElfError::Truncated);
        assert_eq!(
            Elf::parse(b"\x7fELF\x02\x01\x01").unwrap_err(),
            ElfError::Truncated
        );
        let mut be = elf64(ET_EXEC, 0, &[], 64, &[], &[]);
        be[5] = 2;
        assert_eq!(
            Elf::parse(&be).unwrap_err(),
            ElfError::Unsupported("big-endian")
        );
    }

    #[test]
    fn headers_sections_interp_and_dynamic_strings_are_read() {
        // PT_INTERP at 0x200, PT_DYNAMIC with DT_STRTAB → the .dynstr
        let interp = b"/lib64/ld-linux-x86-64.so.2\0";
        let dynstr = b"\0libc.so.6\0ptrace\0puts\0".to_vec();
        let body_off = 0x200;
        let mut body = interp.to_vec();
        body.resize(0x100, 0);
        let dynstr_off = (body_off + body.len()) as u64;
        body.extend_from_slice(&dynstr);
        body.resize(0x200, 0);
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
        let total = (body_off + body.len()) as u64;
        let phs = [
            Ph {
                kind: PT_INTERP,
                flags: PF_R,
                offset: body_off as u64,
                vaddr: 0,
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
        let img = elf64(ET_DYN, 0x40_0000 + 0x200, &phs, body_off, &body, &[]);
        let e = Elf::parse(&img).unwrap();
        assert_eq!(e.describe(), "elf64-x86_64-dyn");
        assert_eq!(e.segments().len(), 3);
        assert_eq!(e.interp(), Some("/lib64/ld-linux-x86-64.so.2"));
        assert!(e.dynamic().contains(&(DT_NEEDED, 1)));
        let strs = e.dynamic_strings();
        assert!(
            strs.contains(&"ptrace") && strs.contains(&"libc.so.6"),
            "{strs:?}"
        );
        assert!(e.sections().is_empty());
    }

    #[test]
    fn section_names_come_from_shstrtab() {
        let shs = [
            Sh {
                name: ".text",
                kind: 1,
                flags: SHF_EXECINSTR | 2,
                content: code(64),
                link: 0,
            },
            Sh {
                name: ".symtab",
                kind: SHT_SYMTAB,
                flags: 0,
                content: vec![0; 24],
                link: 0,
            },
        ];
        let img = elf64(ET_EXEC, 0, &[], 64, &[], &shs);
        let e = Elf::parse(&img).unwrap();
        let secs = e.sections();
        assert_eq!(secs.len(), 4);
        let names: Vec<_> = secs
            .iter()
            .filter_map(|s| e.section_name(&secs, s))
            .collect();
        assert_eq!(names, ["", ".text", ".symtab", ".shstrtab"]);
    }

    #[test]
    fn hostile_headers_only_shorten_what_is_read() {
        let mut img = elf64(ET_EXEC, 0, &[], 64, &[], &[]);
        // phnum 65535 at an offset past the end, shnum 65535 likewise
        img[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        img[56..58].copy_from_slice(&u16::MAX.to_le_bytes());
        img[40..48].copy_from_slice(&(u64::MAX - 10).to_le_bytes());
        img[60..62].copy_from_slice(&u16::MAX.to_le_bytes());
        let e = Elf::parse(&img).unwrap();
        assert!(e.segments().is_empty());
        assert!(e.sections().is_empty());
        assert!(e.interp().is_none());
        assert!(e.dynamic_strings().is_empty());
        assert_eq!(e.program_headers_end(), u64::MAX);
    }
}
