//! Boot-time BTF offset revalidation (BUG-036).
//!
//! The eBPF half compiles in fixed kernel struct offsets
//! ([`common::btf_offsets`]) because aya-ebpf 0.1 has no CO-RE. If the
//! running kernel's struct layout differs from what those offsets
//! assume (a kernel upgrade, a different distro), every dependent LSM
//! decision and sensor read operates on the WRONG kernel memory —
//! silently. This module reads the running kernel's BTF
//! (`/sys/kernel/btf/vmlinux`), re-derives each offset, and compares it
//! to the compiled-in value. On any mismatch the agent refuses to start
//! (the caller exits 78 / `EX_CONFIG`) rather than attach hooks that
//! read garbage.
//!
//! ## Why we parse BTF ourselves
//!
//! aya 0.13 / aya-obj 0.2 expose no public way to read a struct
//! member's offset: there is no `type_by_id`, and `Struct.members` /
//! `member_bit_offset` are `pub(crate)`. `id_by_type_name_kind` proves
//! a type *exists* but reveals nothing about its layout. The BTF binary
//! format is small and stable, and this is the heart of the fail-closed
//! gate — owning it (no external dependency for the core of the trust
//! mechanism) is deliberate. The parser is read-only, has no `unsafe`,
//! and bounds-checks every access.
//!
//! ## Resolution
//!
//! A `(struct, field_path)` is walked component-by-component. Each
//! component is matched against the current struct's members,
//! descending transparently through *anonymous* union/struct members
//! (this is how `sock_common`'s `skc_*` fields inside its anon unions,
//! and `qstr.len` inside its `hash_len` union, resolve). A multi-element
//! path descends into the resolved member type for the next component
//! (embedded structs only — never through pointers).

use std::collections::HashMap;
use std::fmt;
use std::fs;

use common::btf_offsets::{OffsetSpec, REVALIDATE};

/// The running kernel's BTF, exported by the kernel when built with
/// `CONFIG_DEBUG_INFO_BTF=y` (every supported target kernel).
const VMLINUX_BTF: &str = "/sys/kernel/btf/vmlinux";

/// BTF magic in native byte order; used to detect endianness.
const BTF_MAGIC: u16 = 0xeB9F;

/// Guard on anonymous-member recursion depth (real BTF nesting is
/// shallow; this bounds against pathological/cyclic input).
const MAX_DESCENT: u8 = 8;

// BTF type kinds (uapi/linux/btf.h).
const KIND_INT: u32 = 1;
const KIND_PTR: u32 = 2;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_FWD: u32 = 7;
const KIND_TYPEDEF: u32 = 8;
const KIND_VOLATILE: u32 = 9;
const KIND_CONST: u32 = 10;
const KIND_RESTRICT: u32 = 11;
const KIND_FUNC: u32 = 12;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_FLOAT: u32 = 16;
const KIND_DECL_TAG: u32 = 17;
const KIND_TYPE_TAG: u32 = 18;
const KIND_ENUM64: u32 = 19;

// ───────────────────────────── public API ────────────────────────────

/// Outcome of revalidating every [`REVALIDATE`] entry against the
/// running kernel.
#[derive(Debug)]
pub enum RevalidateOutcome {
    /// All offsets matched. Safe to attach.
    Verified { count: usize },
    /// `/sys/kernel/btf/vmlinux` is absent/unreadable. The eBPF LSM
    /// hooks themselves need BTF to attach, so on such a kernel they
    /// won't attach and these offsets are never read — degrade (WARN),
    /// don't refuse. Matches the existing BTF-absent posture in `main`.
    SkippedNoBtf { reason: String },
    /// Refuse to start (caller exits 78). Either drift was found, or
    /// BTF is present but unparseable (aya may still attach hooks with
    /// unverified offsets — fail closed).
    Refuse(RefuseReason),
}

/// Why a [`RevalidateOutcome::Refuse`] was returned.
#[derive(Debug)]
pub enum RefuseReason {
    /// One or more offsets did not match running-kernel BTF.
    Drift(Vec<Mismatch>),
    /// BTF was present but could not be parsed.
    ParseError(String),
}

/// A single offset that failed revalidation.
#[derive(Debug)]
pub struct Mismatch {
    /// The const's identifier (from [`OffsetSpec::name`]).
    pub name: &'static str,
    /// The BTF struct it was resolved against.
    pub struct_name: &'static str,
    /// The compiled-in byte offset.
    pub expected: usize,
    /// The byte offset derived from running-kernel BTF, or `None` if
    /// the struct/field could not be resolved at all.
    pub actual: Option<usize>,
    /// Human-readable detail (the derived value, or why resolution
    /// failed).
    pub detail: String,
}

/// Read the running kernel's BTF and revalidate every compiled-in
/// offset. Never panics; never reads kernel memory (BTF is a static
/// description). See [`RevalidateOutcome`] for how the caller acts.
pub fn revalidate_offsets() -> RevalidateOutcome {
    let data = match fs::read(VMLINUX_BTF) {
        Ok(d) => d,
        Err(e) => {
            return RevalidateOutcome::SkippedNoBtf {
                reason: format!("{VMLINUX_BTF}: {e}"),
            }
        }
    };
    let btf = match Btf::parse(&data) {
        Ok(b) => b,
        Err(e) => return RevalidateOutcome::Refuse(RefuseReason::ParseError(e.to_string())),
    };
    revalidate_with(&btf, REVALIDATE)
}

/// Core comparison, split out so tests can drive it with synthetic BTF
/// + specs (no real `/sys/kernel/btf/vmlinux` needed).
fn revalidate_with(btf: &Btf, specs: &[OffsetSpec]) -> RevalidateOutcome {
    let mut mismatches = Vec::new();
    for spec in specs {
        match btf.resolve_path(spec.struct_name, spec.field_path) {
            Ok(actual) if actual == spec.expected => {}
            Ok(actual) => mismatches.push(Mismatch {
                name: spec.name,
                struct_name: spec.struct_name,
                expected: spec.expected,
                actual: Some(actual),
                detail: format!("derived byte {actual}, expected {}", spec.expected),
            }),
            Err(e) => mismatches.push(Mismatch {
                name: spec.name,
                struct_name: spec.struct_name,
                expected: spec.expected,
                actual: None,
                detail: e.to_string(),
            }),
        }
    }
    if mismatches.is_empty() {
        RevalidateOutcome::Verified { count: specs.len() }
    } else {
        RevalidateOutcome::Refuse(RefuseReason::Drift(mismatches))
    }
}

// ──────────────────────────── BTF parser ─────────────────────────────

/// BTF parse failure (malformed header, OOB read, unknown kind).
#[derive(Debug)]
pub struct ParseError(String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BTF parse error: {}", self.0)
    }
}
impl std::error::Error for ParseError {}

/// Failure to resolve a `(struct, field_path)` against parsed BTF.
#[derive(Debug)]
enum ResolveError {
    StructNotFound(String),
    NotAStruct(String),
    FieldNotFound(String),
    BitfieldNotByteAligned(String),
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolveError::StructNotFound(s) => write!(f, "struct '{s}' not in kernel BTF"),
            ResolveError::NotAStruct(s) => write!(f, "'{s}' is not a struct/union"),
            ResolveError::FieldNotFound(s) => write!(f, "field '{s}' not found"),
            ResolveError::BitfieldNotByteAligned(s) => {
                write!(f, "field is bit-packed, not byte-aligned ({s})")
            }
        }
    }
}

/// Bounds-checked, endianness-aware reader over the BTF blob (`le` is
/// detected from the magic).
#[derive(Clone, Copy)]
struct Reader<'a> {
    data: &'a [u8],
    le: bool,
}

impl<'a> Reader<'a> {
    fn u32(&self, off: usize) -> Result<u32, ParseError> {
        let b = self
            .data
            .get(off..off + 4)
            .ok_or_else(|| ParseError(format!("u32 read OOB at {off}")))?;
        let arr = [b[0], b[1], b[2], b[3]];
        Ok(if self.le {
            u32::from_le_bytes(arr)
        } else {
            u32::from_be_bytes(arr)
        })
    }
}

/// One struct/union member: its name, its type, and its bit offset
/// within the parent (already de-bitfielded).
struct Member {
    name_off: u32,
    type_id: u32,
    bit_offset: u32,
}

/// The subset of a BTF type we need to navigate offsets.
enum Ty {
    /// A struct or union with its members.
    Composite { members: Vec<Member> },
    /// A type that transparently forwards to another (typedef / const /
    /// volatile / restrict) — followed during navigation.
    Forward { type_id: u32 },
    /// Anything we don't navigate into (int, ptr, enum, array, …). A
    /// pointer is Opaque on purpose: field paths never cross a pointer.
    Opaque,
}

/// Parsed kernel BTF: types indexed by id (0 = void), the string
/// section, and a name→id map for named structs/unions.
struct Btf {
    types: Vec<Ty>,
    strings: Vec<u8>,
    name_to_id: HashMap<String, u32>,
}

impl Btf {
    fn parse(data: &[u8]) -> Result<Btf, ParseError> {
        if data.len() < 24 {
            return Err(ParseError("shorter than BTF header".into()));
        }
        let le = if u16::from_le_bytes([data[0], data[1]]) == BTF_MAGIC {
            true
        } else if u16::from_be_bytes([data[0], data[1]]) == BTF_MAGIC {
            false
        } else {
            return Err(ParseError("bad magic (not BTF)".into()));
        };
        let r = Reader { data, le };
        let hdr_len = r.u32(4)? as usize;
        let type_off = r.u32(8)? as usize;
        let type_len = r.u32(12)? as usize;
        let str_off = r.u32(16)? as usize;
        let str_len = r.u32(20)? as usize;

        let tstart = hdr_len
            .checked_add(type_off)
            .ok_or_else(|| ParseError("type_off overflow".into()))?;
        let tend = tstart
            .checked_add(type_len)
            .ok_or_else(|| ParseError("type_len overflow".into()))?;
        let sstart = hdr_len
            .checked_add(str_off)
            .ok_or_else(|| ParseError("str_off overflow".into()))?;
        let send = sstart
            .checked_add(str_len)
            .ok_or_else(|| ParseError("str_len overflow".into()))?;
        if tend > data.len() || send > data.len() {
            return Err(ParseError("type/str section out of bounds".into()));
        }
        let strings = data[sstart..send].to_vec();

        // id 0 is void; real types are 1-based.
        let mut types = vec![Ty::Opaque];
        let mut name_to_id: HashMap<String, u32> = HashMap::new();

        let mut p = tstart;
        while p + 12 <= tend {
            let name_off = r.u32(p)?;
            let info = r.u32(p + 4)?;
            let size_or_type = r.u32(p + 8)?;
            p += 12;

            let kind = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;
            let kind_flag = (info >> 31) & 1 == 1;
            let id = types.len() as u32;

            match kind {
                KIND_STRUCT | KIND_UNION => {
                    let mut members = Vec::with_capacity(vlen);
                    for i in 0..vlen {
                        let base = p + i * 12;
                        if base + 12 > tend {
                            return Err(ParseError(format!("member OOB in type {id}")));
                        }
                        let m_name = r.u32(base)?;
                        let m_type = r.u32(base + 4)?;
                        let m_off_raw = r.u32(base + 8)?;
                        // kind_flag set ⇒ offset packs bitfield_size in
                        // the high 8 bits; the bit offset is the low 24.
                        let bit_offset = if kind_flag {
                            m_off_raw & 0x00ff_ffff
                        } else {
                            m_off_raw
                        };
                        members.push(Member {
                            name_off: m_name,
                            type_id: m_type,
                            bit_offset,
                        });
                    }
                    p += vlen * 12;
                    if name_off != 0 {
                        if let Ok(nm) = name_at(&strings, name_off) {
                            // First definition wins (BTF defines each
                            // struct once; FWDs are a distinct kind).
                            name_to_id.entry(nm.to_string()).or_insert(id);
                        }
                    }
                    types.push(Ty::Composite { members });
                }
                KIND_TYPEDEF | KIND_CONST | KIND_VOLATILE | KIND_RESTRICT => {
                    types.push(Ty::Forward {
                        type_id: size_or_type,
                    });
                }
                // Fixed-size or no trailing data — skip the trailing and
                // mark Opaque (we never navigate into these).
                KIND_PTR | KIND_FWD | KIND_FUNC | KIND_FLOAT | KIND_TYPE_TAG => {
                    types.push(Ty::Opaque);
                }
                KIND_INT | KIND_VAR | KIND_DECL_TAG => {
                    p += 4;
                    types.push(Ty::Opaque);
                }
                KIND_ARRAY => {
                    p += 12;
                    types.push(Ty::Opaque);
                }
                KIND_ENUM | KIND_FUNC_PROTO => {
                    p += vlen * 8;
                    types.push(Ty::Opaque);
                }
                KIND_DATASEC | KIND_ENUM64 => {
                    p += vlen * 12;
                    types.push(Ty::Opaque);
                }
                other => {
                    // DELIBERATE fail-closed, NOT a gap to "fix" by
                    // skipping: an unknown kind has an unknown trailing
                    // size, so advancing past it by a guess would desync
                    // the type walk and silently mis-resolve every later
                    // offset. We refuse instead. Consequence to know: a
                    // FUTURE kernel that adds a new BTF kind ANYWHERE in
                    // the type section refuses-to-start here even if the
                    // 38 target structs are parseable — at which point
                    // this match must be EXTENDED with the new kind's
                    // trailing size (BTF format evolution), never made to
                    // skip-and-continue.
                    return Err(ParseError(format!(
                        "unknown BTF kind {other} at type id {id}"
                    )));
                }
            }
        }

        Ok(Btf {
            types,
            strings,
            name_to_id,
        })
    }

    /// Follow `Forward` (typedef/cv-qual) chains to the underlying
    /// struct/union id. Returns `None` if the chain doesn't end in a
    /// composite (e.g. it's a pointer/int).
    fn resolve_navigable(&self, mut id: u32) -> Option<u32> {
        for _ in 0..64 {
            match self.types.get(id as usize)? {
                Ty::Composite { .. } => return Some(id),
                Ty::Forward { type_id } => id = *type_id,
                Ty::Opaque => return None,
            }
        }
        None
    }

    /// Find `name` within `struct_id`, descending anonymous members.
    /// Returns `(bit_offset_within_struct, member_type_id)`.
    fn field_offset(&self, struct_id: u32, name: &str, depth: u8) -> Option<(u32, u32)> {
        if depth > MAX_DESCENT {
            return None;
        }
        let Ty::Composite { members } = self.types.get(struct_id as usize)? else {
            return None;
        };
        for m in members {
            let mname = name_at(&self.strings, m.name_off).unwrap_or("");
            if !mname.is_empty() && mname == name {
                return Some((m.bit_offset, m.type_id));
            }
            if m.name_off == 0 {
                // Anonymous member — descend into its composite.
                if let Some(nav) = self.resolve_navigable(m.type_id) {
                    if let Some((inner, tid)) = self.field_offset(nav, name, depth + 1) {
                        return Some((m.bit_offset + inner, tid));
                    }
                }
            }
        }
        None
    }

    /// Resolve a `(struct, field_path)` to a byte offset.
    fn resolve_path(&self, struct_name: &str, field_path: &[&str]) -> Result<usize, ResolveError> {
        let id = *self
            .name_to_id
            .get(struct_name)
            .ok_or_else(|| ResolveError::StructNotFound(struct_name.to_string()))?;
        let mut cur = self
            .resolve_navigable(id)
            .ok_or_else(|| ResolveError::NotAStruct(struct_name.to_string()))?;
        let mut total_bits: u32 = 0;
        for (i, comp) in field_path.iter().enumerate() {
            let (off, mtid) = self
                .field_offset(cur, comp, 0)
                .ok_or_else(|| ResolveError::FieldNotFound(format!("{struct_name}.{comp}")))?;
            total_bits = total_bits.saturating_add(off);
            if i + 1 < field_path.len() {
                cur = self
                    .resolve_navigable(mtid)
                    .ok_or_else(|| ResolveError::NotAStruct((*comp).to_string()))?;
            }
        }
        if total_bits % 8 != 0 {
            return Err(ResolveError::BitfieldNotByteAligned(format!(
                "{total_bits} bits"
            )));
        }
        Ok((total_bits / 8) as usize)
    }
}

/// Read a NUL-terminated string at `off` within the BTF string section.
fn name_at(strings: &[u8], off: u32) -> Result<&str, ParseError> {
    let off = off as usize;
    if off >= strings.len() {
        // off == len is only valid for the empty string at a 0-length
        // section; treat OOB as a parse error.
        if off == 0 {
            return Ok("");
        }
        return Err(ParseError(format!("string offset {off} OOB")));
    }
    let end = strings[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|q| off + q)
        .unwrap_or(strings.len());
    std::str::from_utf8(&strings[off..end]).map_err(|_| ParseError("non-utf8 string".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal BTF encoder for hermetic, kernel-independent tests.
    /// Lays out `[header(24)][types][strings]`; ids are 1-based to
    /// match the parser's void-at-0 convention.
    struct BtfBuilder {
        types: Vec<u8>,
        strings: Vec<u8>,
        next_id: u32,
    }

    impl BtfBuilder {
        fn new() -> Self {
            // strings[0] = NUL ⇒ name_off 0 is the empty (anonymous) name.
            BtfBuilder {
                types: Vec::new(),
                strings: vec![0],
                next_id: 1,
            }
        }

        fn str(&mut self, s: &str) -> u32 {
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(s.as_bytes());
            self.strings.push(0);
            off
        }

        fn push_common(&mut self, name_off: u32, kind: u32, vlen: u32, kind_flag: bool, st: u32) {
            let info = (if kind_flag { 1u32 << 31 } else { 0 }) | (kind << 24) | (vlen & 0xffff);
            self.types.extend_from_slice(&name_off.to_le_bytes());
            self.types.extend_from_slice(&info.to_le_bytes());
            self.types.extend_from_slice(&st.to_le_bytes());
        }

        fn int(&mut self, name: &str) -> u32 {
            let n = self.str(name);
            self.push_common(n, KIND_INT, 0, false, 4);
            self.types.extend_from_slice(&0u32.to_le_bytes()); // int encoding word
            let id = self.next_id;
            self.next_id += 1;
            id
        }

        /// `members`: (name_off, type_id, bit_offset). name_off 0 ⇒ anon.
        fn composite(
            &mut self,
            name: Option<&str>,
            is_union: bool,
            kind_flag: bool,
            members: &[(u32, u32, u32)],
        ) -> u32 {
            let n = name.map(|s| self.str(s)).unwrap_or(0);
            let kind = if is_union { KIND_UNION } else { KIND_STRUCT };
            self.push_common(n, kind, members.len() as u32, kind_flag, 0);
            for &(mn, mt, mo) in members {
                self.types.extend_from_slice(&mn.to_le_bytes());
                self.types.extend_from_slice(&mt.to_le_bytes());
                self.types.extend_from_slice(&mo.to_le_bytes());
            }
            let id = self.next_id;
            self.next_id += 1;
            id
        }

        fn typedef(&mut self, name: &str, refers_to: u32) -> u32 {
            let n = self.str(name);
            self.push_common(n, KIND_TYPEDEF, 0, false, refers_to);
            let id = self.next_id;
            self.next_id += 1;
            id
        }

        fn build(self) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&BTF_MAGIC.to_le_bytes()); // magic
            out.push(1); // version
            out.push(0); // flags
            out.extend_from_slice(&24u32.to_le_bytes()); // hdr_len
            out.extend_from_slice(&0u32.to_le_bytes()); // type_off
            out.extend_from_slice(&(self.types.len() as u32).to_le_bytes()); // type_len
            out.extend_from_slice(&(self.types.len() as u32).to_le_bytes()); // str_off
            out.extend_from_slice(&(self.strings.len() as u32).to_le_bytes()); // str_len
            out.extend_from_slice(&self.types);
            out.extend_from_slice(&self.strings);
            out
        }
    }

    /// Build a fixture exercising every navigation path the real 38 use:
    /// a direct field, an embedded struct, an anonymous union, and a
    /// typedef in the middle of a path.
    fn fixture() -> Vec<u8> {
        let mut b = BtfBuilder::new();
        let u32_id = b.int("u32");
        // inner { x @ byte 8 }
        let x_off = b.str("x");
        let inner = b.composite(Some("inner"), false, false, &[(x_off, u32_id, 64)]);
        // outer { a @ byte 0; emb: inner @ byte 16 }
        let a_off = b.str("a");
        let emb_off = b.str("emb");
        let outer = b.composite(
            Some("outer"),
            false,
            false,
            &[(a_off, u32_id, 0), (emb_off, inner, 128)],
        );
        // anon union { u_field @ 0 }
        let uf_off = b.str("u_field");
        let anon_u = b.composite(None, true, false, &[(uf_off, u32_id, 0)]);
        // withanon { <anon union> @ byte 4 }
        let _withanon = b.composite(Some("withanon"), false, false, &[(0, anon_u, 32)]);
        // typedef outer_td -> outer ; viatd { t: outer_td @ 0 }
        let outer_td = b.typedef("outer_td", outer);
        let t_off = b.str("t");
        let _viatd = b.composite(Some("viatd"), false, false, &[(t_off, outer_td, 0)]);
        // bitfield struct: kind_flag set, member b packed (size 3 @ bit 4)
        let bf_off = b.str("b");
        let _bf = b.composite(Some("bf"), false, true, &[(bf_off, u32_id, (3 << 24) | 4)]);
        b.build()
    }

    fn parsed() -> Btf {
        Btf::parse(&fixture()).expect("fixture parses")
    }

    #[test]
    fn resolves_direct_field() {
        assert_eq!(parsed().resolve_path("outer", &["a"]).unwrap(), 0);
        assert_eq!(parsed().resolve_path("inner", &["x"]).unwrap(), 8);
    }

    #[test]
    fn resolves_embedded_struct_path() {
        // outer.emb @ 16 + inner.x @ 8 = byte 24.
        assert_eq!(parsed().resolve_path("outer", &["emb", "x"]).unwrap(), 24);
    }

    #[test]
    fn resolves_field_in_anonymous_union() {
        // withanon's anon union sits at byte 4; u_field is at +0.
        assert_eq!(parsed().resolve_path("withanon", &["u_field"]).unwrap(), 4);
    }

    #[test]
    fn resolves_through_typedef() {
        // viatd.t is a typedef→outer; .a within outer is byte 0.
        assert_eq!(parsed().resolve_path("viatd", &["t", "a"]).unwrap(), 0);
    }

    #[test]
    fn missing_struct_and_field_error() {
        assert!(matches!(
            parsed().resolve_path("ghost", &["x"]),
            Err(ResolveError::StructNotFound(_))
        ));
        assert!(matches!(
            parsed().resolve_path("outer", &["zzz"]),
            Err(ResolveError::FieldNotFound(_))
        ));
    }

    #[test]
    fn bitfield_member_rejected_as_unaligned() {
        // bf.b is bit-packed at bit 4 — not byte-aligned ⇒ error, never
        // a wrong byte offset.
        assert!(matches!(
            parsed().resolve_path("bf", &["b"]),
            Err(ResolveError::BitfieldNotByteAligned(_))
        ));
    }

    #[test]
    fn revalidate_verified_when_specs_match() {
        let btf = parsed();
        let specs = &[
            OffsetSpec { name: "OUTER_A", struct_name: "outer", field_path: &["a"], expected: 0 },
            OffsetSpec { name: "INNER_X", struct_name: "inner", field_path: &["x"], expected: 8 },
            OffsetSpec { name: "EMB_X", struct_name: "outer", field_path: &["emb", "x"], expected: 24 },
        ];
        match revalidate_with(&btf, specs) {
            RevalidateOutcome::Verified { count } => assert_eq!(count, 3),
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[test]
    fn revalidate_drift_collects_all_mismatches() {
        let btf = parsed();
        let specs = &[
            OffsetSpec { name: "OUTER_A", struct_name: "outer", field_path: &["a"], expected: 0 }, // ok
            OffsetSpec { name: "INNER_X_WRONG", struct_name: "inner", field_path: &["x"], expected: 99 }, // drift
            OffsetSpec { name: "GHOST", struct_name: "ghost", field_path: &["x"], expected: 0 }, // missing
        ];
        match revalidate_with(&btf, specs) {
            RevalidateOutcome::Refuse(RefuseReason::Drift(ms)) => {
                assert_eq!(ms.len(), 2, "collects ALL mismatches, not just the first");
                let wrong = ms.iter().find(|m| m.name == "INNER_X_WRONG").unwrap();
                assert_eq!(wrong.actual, Some(8));
                let ghost = ms.iter().find(|m| m.name == "GHOST").unwrap();
                assert_eq!(ghost.actual, None);
            }
            other => panic!("expected Drift, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_btf_blob() {
        assert!(Btf::parse(&[0u8; 24]).is_err());
        assert!(Btf::parse(b"too short").is_err());
    }

    /// VM-only: derive ALL 38 offsets against the *running* kernel's
    /// real BTF and assert they match the compiled-in values.
    /// `#[ignore]`d so it never runs on a dev box whose kernel differs
    /// from the supported 6.8.x (where the offsets legitimately
    /// differ); run on the target with
    /// `cargo test -p northnarrow-agent --lib btf_revalidate -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn revalidate_real_kernel_btf_all_38_match() {
        match revalidate_offsets() {
            RevalidateOutcome::Verified { count } => {
                assert_eq!(count, 38, "expected all 38 offsets validated");
                eprintln!("OK: all {count} offsets match the running kernel's BTF");
            }
            RevalidateOutcome::SkippedNoBtf { reason } => {
                panic!("no /sys/kernel/btf/vmlinux on this host — cannot run VM check: {reason}");
            }
            RevalidateOutcome::Refuse(RefuseReason::Drift(ms)) => {
                for m in &ms {
                    eprintln!(
                        "DRIFT {}: {}{:?} expected byte {} — {}",
                        m.name, m.struct_name, m.actual, m.expected, m.detail
                    );
                }
                panic!("{} offset(s) drifted on the running kernel (see stderr)", ms.len());
            }
            RevalidateOutcome::Refuse(RefuseReason::ParseError(e)) => {
                panic!("BTF parse error on the running kernel: {e}");
            }
        }
    }
}
