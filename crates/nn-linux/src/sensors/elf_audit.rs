//! The re-check of #578 (R1-1): whether a program names a library for
//! auditing in its dynamic section — `DT_AUDIT` or `DT_DEPAUDIT` — read the
//! way glibc's loader reads it, for the exec pump's step on an exec of the
//! loader ([`super::loader_files`]).
//!
//! glibc's loader reads both tags from the program it was given (the main
//! map) and loads and runs those libraries — their constructors,
//! `la_version` — before its list and trace modes exit (`ld.so --list`,
//! `LD_TRACE_LOADED_OBJECTS`, `ldd`; verified on 2.39). A program that names
//! itself runs its own constructor there. `--verify` exits before.
//!
//! The table is found as the loader finds it: the last `PT_DYNAMIC`'s
//! address, read through the `PT_LOAD` segment that maps it (the last that
//! does: a later segment is mapped over an earlier one), entry after entry
//! up to `DT_NULL` — not the `PT_DYNAMIC`'s own file offset or size, which
//! the loader does not use (a decoy there names nothing). Memory past a
//! segment's file part is zero: a `DT_NULL`. Anything the reader cannot
//! follow as the loader would — not ELF, an entry no segment maps, one
//! across a segment's file end, a table longer than [`MAX_ENTRIES`], a
//! short read — is not known (`None`), never "none".

use std::io;

/// `DT_AUDIT` and `DT_DEPAUDIT` (`elf.h`).
pub const DT_AUDIT: i64 = 0x6fff_fefc;
pub const DT_DEPAUDIT: i64 = 0x6fff_fefb;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
/// `e_phnum`'s escape (the count in section 0): not followed.
const PN_XNUM: u16 = 0xffff;

/// The most program headers read (a program has a dozen): the table is at
/// most `128 * 56` bytes (round 3, R2-2).
pub const MAX_PHDRS: usize = 128;
/// The most dynamic entries read before a `DT_NULL` (a program has a few
/// dozen).
pub const MAX_ENTRIES: usize = 4096;
/// The most bytes one read of the dynamic section takes (round 3, R2-2: no
/// buffer of this reader is larger than this or the program-header table).
pub const CHUNK: u64 = 4 * 1024;

/// What the dynamic section says (`Some`): it names a library for auditing
/// (`true`) or none (`false`, a program with no dynamic section too); `None`
/// when it cannot be read as the loader reads it. `read_at(offset, buf)`
/// fills `buf` from the file at `offset`, returning the bytes read.
pub fn names_an_auditor(
    read_at: &mut dyn FnMut(u64, &mut [u8]) -> io::Result<usize>,
) -> Option<bool> {
    let mut ident = [0u8; 64];
    let n = read_full(read_at, 0, &mut ident)?;
    if n < 52 || &ident[..4] != b"\x7fELF" {
        return None;
    }
    let wide = match ident[4] {
        1 => false,
        2 => true,
        _ => return None,
    };
    let big = match ident[5] {
        1 => false,
        2 => true,
        _ => return None,
    };
    let e = Endian { big };
    if wide && n < 64 {
        return None;
    }
    let (phoff, phentsize, phnum) = if wide {
        (
            e.u64(&ident[0x20..]),
            e.u16(&ident[0x36..]),
            e.u16(&ident[0x38..]),
        )
    } else {
        (
            u64::from(e.u32(&ident[0x1c..])),
            e.u16(&ident[0x2a..]),
            e.u16(&ident[0x2c..]),
        )
    };
    // round 3 (R2-2): glibc refuses any other size, so the table is at most
    // MAX_PHDRS * 56 bytes
    let ent_size: u16 = if wide { 56 } else { 32 };
    if phnum == PN_XNUM || usize::from(phnum) > MAX_PHDRS || (phnum > 0 && phentsize != ent_size) {
        return None;
    }
    let mut table = vec![0u8; usize::from(phentsize) * usize::from(phnum)];
    if read_full(read_at, phoff, &mut table)? < table.len() {
        return None;
    }
    let mut loads: Vec<Segment> = Vec::new();
    let mut dynamic: Option<u64> = None;
    for ph in table.chunks_exact(usize::from(phentsize.max(1))) {
        let (kind, seg) = if wide {
            (
                e.u32(ph),
                Segment {
                    offset: e.u64(&ph[8..]),
                    vaddr: e.u64(&ph[16..]),
                    filesz: e.u64(&ph[32..]),
                    memsz: e.u64(&ph[40..]),
                },
            )
        } else {
            (
                e.u32(ph),
                Segment {
                    offset: u64::from(e.u32(&ph[4..])),
                    vaddr: u64::from(e.u32(&ph[8..])),
                    filesz: u64::from(e.u32(&ph[16..])),
                    memsz: u64::from(e.u32(&ph[20..])),
                },
            )
        };
        match kind {
            PT_LOAD => loads.push(seg),
            // the loader keeps the last one
            PT_DYNAMIC => dynamic = Some(seg.vaddr),
            _ => {}
        }
    }
    // no dynamic section: a static program, nothing loaded for it
    let Some(start) = dynamic else {
        return Some(false);
    };
    let ent: u64 = if wide { 16 } else { 8 };
    let mut at = start;
    let mut entries = 0usize;
    // each round reads at least one entry; bounded all the same
    for _ in 0..MAX_ENTRIES {
        if entries >= MAX_ENTRIES {
            break;
        }
        // the segment that maps the entry: the last one that does
        let seg = loads.iter().rev().find(|s| {
            at >= s.vaddr
                && matches!(
                    (at.checked_add(ent), s.vaddr.checked_add(s.memsz)),
                    (Some(end), Some(top)) if end <= top
                )
        })?;
        let into = at - seg.vaddr;
        if into >= seg.filesz {
            // past the file part: zero, a DT_NULL
            return Some(false);
        }
        if into + ent > seg.filesz {
            return None;
        }
        // as many entries as this segment's file part holds, in one read
        let left = (seg.filesz - into).min(CHUNK) / ent * ent;
        let want = left.min((MAX_ENTRIES - entries) as u64 * ent);
        let mut buf = vec![0u8; want as usize];
        let off = seg.offset.checked_add(into)?;
        if read_full(read_at, off, &mut buf)? < buf.len() {
            return None;
        }
        for d in buf.chunks_exact(ent as usize) {
            let tag = if wide {
                e.u64(d) as i64
            } else {
                i64::from(e.u32(d) as i32)
            };
            if tag == 0 {
                return Some(false);
            }
            if tag == DT_AUDIT || tag == DT_DEPAUDIT {
                return Some(true);
            }
            entries += 1;
        }
        at = at.checked_add(want)?;
    }
    None
}

/// A `PT_LOAD` segment.
#[derive(Clone, Copy, Debug)]
struct Segment {
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
}

/// `buf` filled from `offset` as far as the file goes; the bytes read,
/// `None` on an error.
fn read_full(
    read_at: &mut dyn FnMut(u64, &mut [u8]) -> io::Result<usize>,
    offset: u64,
    buf: &mut [u8],
) -> Option<usize> {
    let mut done = 0;
    while done < buf.len() {
        match read_at(offset.checked_add(done as u64)?, &mut buf[done..]) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    Some(done)
}

/// The file's byte order.
#[derive(Clone, Copy)]
struct Endian {
    big: bool,
}

impl Endian {
    fn u16(self, b: &[u8]) -> u16 {
        let a = [b[0], b[1]];
        if self.big {
            u16::from_be_bytes(a)
        } else {
            u16::from_le_bytes(a)
        }
    }

    fn u32(self, b: &[u8]) -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if self.big {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    }

    fn u64(self, b: &[u8]) -> u64 {
        let a = [b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]];
        if self.big {
            u64::from_be_bytes(a)
        } else {
            u64::from_le_bytes(a)
        }
    }
}

/// Test images: a 64-bit little-endian ELF (or 32-bit, or big-endian) with
/// the program headers and dynamic entries asked for.
#[cfg(test)]
pub(crate) mod image {
    /// A program header: type, file offset, address, file and memory size.
    pub type Ph = (u32, u64, u64, u64, u64);

    /// An image of `class` (1: 32-bit, 2: 64-bit), `big`-endian or not,
    /// its program headers `phs` right after the header, each of `blobs`
    /// (offset, bytes) written at its offset, as long as its `PT_LOAD`s'
    /// file parts.
    pub fn build(class: u8, big: bool, phs: &[Ph], blobs: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let wide = class == 2;
        let (ehsize, phentsize) = if wide { (64usize, 56usize) } else { (52, 32) };
        let mut out = vec![0u8; ehsize + phentsize * phs.len()];
        out[..4].copy_from_slice(b"\x7fELF");
        out[4] = class;
        out[5] = if big { 2 } else { 1 };
        out[6] = 1;
        let put = |out: &mut Vec<u8>, at: usize, v: u64, n: usize| {
            let bytes = if big {
                v.to_be_bytes()[8 - n..].to_vec()
            } else {
                v.to_le_bytes()[..n].to_vec()
            };
            out[at..at + n].copy_from_slice(&bytes);
        };
        put(&mut out, 0x10, 3, 2); // ET_DYN
        if wide {
            put(&mut out, 0x20, ehsize as u64, 8);
            put(&mut out, 0x36, phentsize as u64, 2);
            put(&mut out, 0x38, phs.len() as u64, 2);
        } else {
            put(&mut out, 0x1c, ehsize as u64, 4);
            put(&mut out, 0x2a, phentsize as u64, 2);
            put(&mut out, 0x2c, phs.len() as u64, 2);
        }
        for (i, (kind, offset, vaddr, filesz, memsz)) in phs.iter().enumerate() {
            let b = ehsize + i * phentsize;
            put(&mut out, b, u64::from(*kind), 4);
            if wide {
                put(&mut out, b + 8, *offset, 8);
                put(&mut out, b + 16, *vaddr, 8);
                put(&mut out, b + 32, *filesz, 8);
                put(&mut out, b + 40, *memsz, 8);
            } else {
                put(&mut out, b + 4, *offset, 4);
                put(&mut out, b + 8, *vaddr, 4);
                put(&mut out, b + 16, *filesz, 4);
                put(&mut out, b + 20, *memsz, 4);
            }
        }
        for (at, bytes) in blobs {
            let end = *at as usize + bytes.len();
            if out.len() < end {
                out.resize(end, 0);
            }
            out[*at as usize..end].copy_from_slice(bytes);
        }
        // the file as long as its segments say
        let end = phs
            .iter()
            .filter(|p| p.0 == 1)
            .map(|p| (p.1 + p.3) as usize)
            .max()
            .unwrap_or(0);
        if out.len() < end {
            out.resize(end, 0);
        }
        out
    }

    /// Dynamic entries `(tag, value)` encoded for `class` and `big`.
    pub fn dynamic(class: u8, big: bool, entries: &[(i64, u64)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (tag, val) in entries {
            if class == 2 {
                let (t, v) = if big {
                    (tag.to_be_bytes(), val.to_be_bytes())
                } else {
                    (tag.to_le_bytes(), val.to_le_bytes())
                };
                out.extend_from_slice(&t);
                out.extend_from_slice(&v);
            } else {
                let (t, v) = if big {
                    ((*tag as i32).to_be_bytes(), (*val as u32).to_be_bytes())
                } else {
                    ((*tag as i32).to_le_bytes(), (*val as u32).to_le_bytes())
                };
                out.extend_from_slice(&t);
                out.extend_from_slice(&v);
            }
        }
        out
    }

    /// A 64-bit little-endian program: one `PT_LOAD` mapping the whole file
    /// at address 0x1000 less nothing (offset = address), its dynamic
    /// section at 0x400 holding `entries`.
    pub fn program(entries: &[(i64, u64)]) -> Vec<u8> {
        let dynamic = dynamic(2, false, entries);
        let size = 0x400 + dynamic.len() as u64;
        build(
            2,
            false,
            &[
                (1, 0, 0, size, size),
                (2, 0x400, 0x400, dynamic.len() as u64, dynamic.len() as u64),
            ],
            &[(0x400, dynamic)],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::image::{build, dynamic, program};
    use super::*;

    const DT_NEEDED: i64 = 1;
    const DT_STRTAB: i64 = 5;
    const DT_DEBUG: i64 = 21;

    fn read(img: &[u8]) -> Option<bool> {
        let mut at = |off: u64, buf: &mut [u8]| -> io::Result<usize> {
            let off = off as usize;
            if off >= img.len() {
                return Ok(0);
            }
            let n = buf.len().min(img.len() - off);
            buf[..n].copy_from_slice(&img[off..off + n]);
            Ok(n)
        };
        names_an_auditor(&mut at)
    }

    /// The re-check of #578 (R1-1, named): a program that names a library
    /// for auditing — `DT_AUDIT` (another library, or itself: the tag holds
    /// a string either way) or `DT_DEPAUDIT` — is told; one that names
    /// none, or has no dynamic section, is "none".
    #[test]
    fn a_program_naming_a_library_for_auditing_is_told_from_one_naming_none() {
        let common = [(DT_NEEDED, 1), (DT_STRTAB, 0x300), (DT_DEBUG, 0)];
        let with = |tag: i64| {
            let mut e = common.to_vec();
            e.push((tag, 9));
            e.push((0, 0));
            program(&e)
        };
        assert_eq!(read(&with(DT_AUDIT)), Some(true), "DT_AUDIT");
        assert_eq!(read(&with(DT_DEPAUDIT)), Some(true), "DT_DEPAUDIT");
        let mut none = common.to_vec();
        none.push((0, 0));
        assert_eq!(read(&program(&none)), Some(false), "none");
        // a tag after DT_NULL is not read by the loader
        let mut after = common.to_vec();
        after.push((0, 0));
        after.push((DT_AUDIT, 9));
        assert_eq!(read(&program(&after)), Some(false), "after DT_NULL");
        // no PT_DYNAMIC: a static program
        let static_ = build(2, false, &[(1, 0, 0, 0x100, 0x100)], &[]);
        assert_eq!(read(&static_), Some(false), "static");
        // 32-bit, and big-endian
        for (class, big) in [(1u8, false), (1, true), (2, true)] {
            let d = dynamic(class, big, &[(DT_STRTAB, 0x300), (DT_AUDIT, 9), (0, 0)]);
            let size = 0x400 + d.len() as u64;
            let img = build(
                class,
                big,
                &[
                    (1, 0, 0, size, size),
                    (2, 0x400, 0x400, d.len() as u64, d.len() as u64),
                ],
                &[(0x400, d)],
            );
            assert_eq!(read(&img), Some(true), "class {class} big {big}");
        }
    }

    /// The re-check of #578 (R1-1, named): the table is read where the
    /// loader reads it — the last `PT_DYNAMIC`'s ADDRESS through the
    /// `PT_LOAD` that maps it, up to `DT_NULL` — not at the `PT_DYNAMIC`'s
    /// own file offset (a decoy naming none there), and past its stated
    /// size; an entry past a segment's file part is zero (a `DT_NULL`).
    #[test]
    fn the_dynamic_table_is_read_where_the_loader_maps_it() {
        let real = dynamic(2, false, &[(DT_STRTAB, 0x300), (DT_AUDIT, 9), (0, 0)]);
        let decoy = dynamic(2, false, &[(DT_STRTAB, 0x300), (0, 0)]);
        // address 0x2400 is mapped from file offset 0x800 (segment at 0x2000
        // from offset 0x400); the PT_DYNAMIC's offset field points at the decoy
        let img = build(
            2,
            false,
            &[
                (1, 0, 0, 0x400, 0x400),
                (1, 0x400, 0x2000, 0x430, 0x430),
                (2, 0x600, 0x2400, 16, 16),
            ],
            &[(0x600, decoy.clone()), (0x800, real.clone())],
        );
        assert_eq!(read(&img), Some(true), "through the segment, past p_memsz");
        // two PT_DYNAMIC: the last one is the loader's
        let img = build(
            2,
            false,
            &[
                (1, 0, 0, 0x1000, 0x1000),
                (2, 0x400, 0x400, 32, 32),
                (2, 0x800, 0x800, 32, 32),
            ],
            &[(0x400, real.clone()), (0x800, decoy.clone())],
        );
        assert_eq!(read(&img), Some(false), "the last PT_DYNAMIC");
        // overlapping PT_LOADs: the later one is mapped over the earlier
        let img = build(
            2,
            false,
            &[
                (1, 0, 0, 0x1000, 0x1000),
                (1, 0x800, 0x400, 0x100, 0x100),
                (2, 0x400, 0x400, 48, 48),
            ],
            &[(0x400, decoy.clone()), (0x800, real.clone())],
        );
        assert_eq!(read(&img), Some(true), "the last PT_LOAD mapping it");
        // the table starts past the segment's file part: zero memory
        let img = build(
            2,
            false,
            &[(1, 0, 0, 0x400, 0x2000), (2, 0x1000, 0x1000, 32, 32)],
            &[],
        );
        assert_eq!(read(&img), Some(false), "in the zeroed part");
    }

    /// The re-check of #578 (R1-1, named): what the reader cannot follow as
    /// the loader would is not known — never "none": not ELF, a short
    /// header, a table no segment maps, an entry across a segment's file
    /// end, no `DT_NULL` within [`MAX_ENTRIES`], a short read.
    #[test]
    fn a_dynamic_section_the_reader_cannot_follow_is_not_known() {
        assert_eq!(read(b"#!/bin/sh\necho hi\n"), None, "not ELF");
        assert_eq!(read(b"\x7fELF\x02\x01"), None, "short header");
        let d = dynamic(2, false, &[(DT_STRTAB, 1), (0, 0)]);
        let unmapped = build(
            2,
            false,
            &[(1, 0, 0, 0x100, 0x100), (2, 0x400, 0x4000, 32, 32)],
            &[(0x400, d.clone())],
        );
        assert_eq!(read(&unmapped), None, "no segment maps it");
        let across = build(
            2,
            false,
            &[(1, 0, 0, 0x408, 0x1000), (2, 0x400, 0x400, 32, 32)],
            &[(0x400, d.clone())],
        );
        assert_eq!(read(&across), None, "across the file part's end");
        let endless: Vec<(i64, u64)> = (0..MAX_ENTRIES as u64 + 8).map(|i| (DT_DEBUG, i)).collect();
        assert_eq!(read(&program(&endless)), None, "no DT_NULL in reach");
        // the file shorter than its segment says: a short read
        let mut short = program(&[(DT_STRTAB, 1), (DT_DEBUG, 0), (0, 0)]);
        short.truncate(0x408);
        assert_eq!(read(&short), None, "short read");
        // a read error
        let mut failing = |_: u64, _: &mut [u8]| -> io::Result<usize> {
            Err(io::Error::from_raw_os_error(libc::EIO))
        };
        assert_eq!(names_an_auditor(&mut failing), None, "EIO");
    }

    /// Fix round 3 of #578 (R2-2, named): the header's escapes. Glibc
    /// refuses an `e_phentsize` that is not the class's program header's
    /// size, so the reader does too — and asks for no table larger than
    /// [`MAX_PHDRS`] headers.
    #[test]
    fn a_header_with_a_wrong_program_header_size_or_count_is_not_known() {
        let good = program(&[(DT_STRTAB, 1), (DT_AUDIT, 9), (0, 0)]);
        assert_eq!(read(&good), Some(true), "control");
        for (name, at, val) in [
            ("phentsize too small", 0x36usize, 32u16),
            ("phentsize one too large", 0x36, 57),
            ("phentsize 0xffff", 0x36, 0xffff),
            ("phentsize zero", 0x36, 0),
            ("phnum is PN_XNUM", 0x38, 0xffff),
            ("phnum past the cap", 0x38, MAX_PHDRS as u16 + 1),
            ("phnum 1024", 0x38, 1024),
        ] {
            let mut img = good.clone();
            img[at..at + 2].copy_from_slice(&val.to_le_bytes());
            assert_eq!(read(&img), None, "{name}");
        }
        // 32-bit: 56 is the 64-bit size
        let mut img = build(1, false, &[(1, 0, 0, 0x400, 0x400)], &[]);
        img[0x2a..0x2c].copy_from_slice(&56u16.to_le_bytes());
        assert_eq!(read(&img), None, "32-bit with the 64-bit size");
    }

    /// Fix round 3 of #578 (R2-2, named): no read of the reader is larger
    /// than one program-header table or one chunk, whatever the header
    /// says.
    #[test]
    fn no_buffer_of_the_reader_is_larger_than_its_fixed_bound() {
        let good = program(&[(DT_STRTAB, 1), (DT_DEBUG, 0), (0, 0)]);
        let bound = (MAX_PHDRS * 56).max(CHUNK as usize);
        for (phentsize, phnum) in [
            (0xffffu16, 1024u16),
            (56, 128),
            (56, 1024),
            (0xffff, 0xffff),
            (56, 0),
        ] {
            let mut img = good.clone();
            img[0x36..0x38].copy_from_slice(&phentsize.to_le_bytes());
            img[0x38..0x3a].copy_from_slice(&phnum.to_le_bytes());
            let mut most = 0usize;
            let mut at = |_: u64, buf: &mut [u8]| -> io::Result<usize> {
                most = most.max(buf.len());
                buf.fill(0);
                Ok(buf.len())
            };
            let _ = names_an_auditor(&mut at);
            assert!(most <= bound, "{phentsize}x{phnum}: {most}");
        }
        // an endless table of entries: read in chunks
        let endless: Vec<(i64, u64)> = (0..MAX_ENTRIES as u64 + 8).map(|i| (DT_DEBUG, i)).collect();
        let img = program(&endless);
        let mut most = 0usize;
        let mut at = |off: u64, buf: &mut [u8]| -> io::Result<usize> {
            most = most.max(buf.len());
            let off = off as usize;
            if off >= img.len() {
                return Ok(0);
            }
            let n = buf.len().min(img.len() - off);
            buf[..n].copy_from_slice(&img[off..off + n]);
            Ok(n)
        };
        assert_eq!(names_an_auditor(&mut at), None);
        assert!(most <= bound, "{most}");
    }
}
