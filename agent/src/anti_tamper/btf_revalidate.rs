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
use std::sync::OnceLock;

use common::btf_offsets::{
    EnumSpec, OffsetSpec, BTF_MODULE_STRUCTS, BTF_OFFSETS_ABSENT, BTF_OFFSETS_MAGIC,
    ENUM_SLOT_TABLE, ENUM_VALUES, REVALIDATE, SLOT_TABLE,
};

/// The running kernel's BTF, exported by the kernel when built with
/// `CONFIG_DEBUG_INFO_BTF=y` (every supported target kernel).
const VMLINUX_BTF: &str = "/sys/kernel/btf/vmlinux";

/// BTF magic in native byte order; used to detect endianness.
const BTF_MAGIC: u16 = 0xEB9F; // kernel docs write it `0xeB9F`

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
#[derive(Debug, Clone)]
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

// ── runtime offsets (multi-kernel, level 1) ───────────────────────────

/// Every [`REVALIDATE`] offset resolved from the running kernel.
#[derive(Debug, Clone)]
pub struct ResolvedOffsets {
    /// `(slot, byte offset)` ready to be written into the eBPF
    /// `BTF_OFFSETS` map (slot numbers from [`SLOT_TABLE`]).
    pub values: Vec<(u32, u32)>,
    /// Offsets whose resolved value differs from the compiled-in
    /// constant. Informational: the map carries the right value, the
    /// constant is only the fallback for an unarmed map.
    pub drifted: Vec<Mismatch>,
    /// Optional entries this kernel does not have (slot written as
    /// [`BTF_OFFSETS_ABSENT`]): the dependent feature degrades.
    pub absent: Vec<Mismatch>,
    /// Kernel modules whose BTF was not found next to the vmlinux BTF
    /// (`/sys/kernel/btf/<module>`): their entries are written as
    /// [`BTF_OFFSETS_ABSENT`] without counting as a degradation. Without
    /// the module there is nothing of its types to read (review 55:
    /// btrfs).
    pub modules_not_loaded: Vec<&'static str>,
}

/// Outcome of [`resolve_offsets`].
#[derive(Debug)]
pub enum ResolveOutcome {
    /// Every offset resolved (drift, if any, is listed inside).
    Resolved(ResolvedOffsets),
    /// `/sys/kernel/btf/vmlinux` is absent: nothing can be resolved and
    /// the LSM hooks will not attach either; the compiled-in constants
    /// stay in force for whatever does attach.
    SkippedNoBtf { reason: String },
    /// BTF unparseable, or at least one field does not exist on this
    /// kernel — refuse to start (fail-closed, BUG-036).
    Refuse(RefuseReason),
}

/// Resolve every offset from the running kernel's BTF. A kernel whose
/// layout merely differs from the build is **supported** (the values go
/// into the map); a kernel missing a field is refused.
pub fn resolve_offsets() -> ResolveOutcome {
    resolve_offsets_from(std::path::Path::new(VMLINUX_BTF))
}

/// Byte offsets of arbitrary `struct.field.path` queries against a BTF
/// blob — for the Tappa 10.9 sensor-feasibility probes, whose fields the
/// production [`REVALIDATE`] table does not carry yet. One entry per query:
/// `Ok(offset)` or the resolver's reason. `Err` when the blob cannot be read
/// or parsed.
pub fn resolve_fields_from(
    path: &std::path::Path,
    queries: &[(&str, &[&str])],
) -> Result<Vec<Result<usize, String>>, String> {
    let data = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let btf = Btf::parse(&data).map_err(|e| e.to_string())?;
    Ok(queries
        .iter()
        .map(|(st, fp)| btf.resolve_path(st, fp).map_err(|e| e.to_string()))
        .collect())
}

/// [`resolve_offsets`] against an arbitrary BTF blob (a `vmlinux` BTF
/// extracted from a distro kernel, a BTFHub file, another host's
/// `/sys/kernel/btf/vmlinux`). Powers `northnarrow-agent --btf-check`
/// and the computed kernel matrix (multi-kernel, level 2).
pub fn resolve_offsets_from(path: &std::path::Path) -> ResolveOutcome {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            return ResolveOutcome::SkippedNoBtf {
                reason: format!("{}: {e}", path.display()),
            }
        }
    };
    let btf = match Btf::parse(&data) {
        Ok(b) => b,
        Err(e) => return ResolveOutcome::Refuse(RefuseReason::ParseError(e.to_string())),
    };
    // Module BTFs sit next to the kernel's in the sysfs layout
    // (`/sys/kernel/btf/btrfs`); a copied pair keeps the same names.
    let dir = (path.file_name() == Some(std::ffi::OsStr::new("vmlinux")))
        .then(|| path.parent())
        .flatten();
    let modules = |m: &str| dir.and_then(|d| fs::read(d.join(m)).ok());
    resolve_with(&btf, REVALIDATE, ENUM_VALUES, &modules)
}

/// `spec` against `t`, trying the alternative paths in order.
fn resolve_spec<T: TypeTable>(t: &T, spec: &OffsetSpec) -> Result<usize, ResolveError> {
    let mut resolved = t.resolve_path(spec.struct_name, spec.field_path);
    if resolved.is_err() {
        for alt in spec.alt_paths {
            if let Ok(v) = t.resolve_path(spec.struct_name, alt) {
                resolved = Ok(v);
                break;
            }
        }
    }
    resolved
}

/// `modules(name)`: the BTF of kernel module `name`, `None` when it is not
/// loaded. Consulted only for the structs [`BTF_MODULE_STRUCTS`] lists,
/// when vmlinux does not carry them (module not built in).
fn resolve_with(
    btf: &Btf,
    specs: &[OffsetSpec],
    enums: &[EnumSpec],
    modules: &dyn Fn(&str) -> Option<Vec<u8>>,
) -> ResolveOutcome {
    let mut values = Vec::with_capacity(specs.len());
    let mut drifted = Vec::new();
    let mut missing = Vec::new();
    let mut absent = Vec::new();
    let mut modules_not_loaded: Vec<&'static str> = Vec::new();
    // Each module's BTF parsed once: Err(None) = not loaded here,
    // Err(Some(reason)) = unparseable.
    let mut split: HashMap<&'static str, Result<SplitBtf<'_>, Option<String>>> = HashMap::new();
    for spec in specs {
        let slot = SLOT_TABLE
            .iter()
            .find(|(n, _)| *n == spec.name)
            .map(|(_, s)| *s);
        let mut resolved = resolve_spec(btf, spec);
        let module = BTF_MODULE_STRUCTS
            .iter()
            .find(|(st, _)| *st == spec.struct_name)
            .map(|(_, m)| *m);
        if let (Err(_), Some(module)) = (&resolved, module) {
            let entry = split
                .entry(module)
                .or_insert_with(|| match modules(module) {
                    None => Err(None),
                    Some(data) => SplitBtf::parse(btf, &data).map_err(|e| Some(e.to_string())),
                });
            match entry {
                Ok(sb) => resolved = resolve_spec(sb, spec),
                Err(Some(reason)) => {
                    resolved = Err(ResolveError::ModuleBtf(format!("{module}: {reason}")))
                }
                Err(None) => {
                    if let (true, Some(slot)) = (spec.optional, slot) {
                        values.push((slot, BTF_OFFSETS_ABSENT));
                        if !modules_not_loaded.contains(&module) {
                            modules_not_loaded.push(module);
                        }
                        continue;
                    }
                    resolved = Err(ResolveError::ModuleBtf(format!(
                        "{module} module BTF not found"
                    )));
                }
            }
        }
        match (resolved, slot) {
            (Ok(actual), Some(slot)) => {
                if actual != spec.expected {
                    drifted.push(Mismatch {
                        name: spec.name,
                        struct_name: spec.struct_name,
                        expected: spec.expected,
                        actual: Some(actual),
                        detail: format!("compiled {} → runtime {actual}", spec.expected),
                    });
                }
                values.push((slot, actual as u32));
            }
            (Ok(_), None) => missing.push(Mismatch {
                name: spec.name,
                struct_name: spec.struct_name,
                expected: spec.expected,
                actual: None,
                detail: "no BTF_OFFSETS slot for this spec (SLOT_TABLE out of sync)".into(),
            }),
            (Err(e), Some(slot)) if spec.optional => {
                values.push((slot, BTF_OFFSETS_ABSENT));
                absent.push(Mismatch {
                    name: spec.name,
                    struct_name: spec.struct_name,
                    expected: spec.expected,
                    actual: None,
                    detail: e.to_string(),
                });
            }
            (Err(e), _) => missing.push(Mismatch {
                name: spec.name,
                struct_name: spec.struct_name,
                expected: spec.expected,
                actual: None,
                detail: e.to_string(),
            }),
        }
    }
    for e in enums {
        let slot = ENUM_SLOT_TABLE
            .iter()
            .find(|(n, _)| *n == e.name)
            .map(|(_, s)| *s);
        match (btf.resolve_enum(e.enum_name, e.value_name), slot) {
            (Ok(v), Some(slot)) => {
                if v as u32 != e.compiled {
                    drifted.push(Mismatch {
                        name: e.name,
                        struct_name: e.enum_name,
                        expected: e.compiled as usize,
                        actual: Some(v as usize),
                        detail: format!("enum value compiled {} → runtime {v}", e.compiled),
                    });
                }
                values.push((slot, v as u32));
            }
            (Err(err), Some(slot)) if e.optional => {
                values.push((slot, BTF_OFFSETS_ABSENT));
                absent.push(Mismatch {
                    name: e.name,
                    struct_name: e.enum_name,
                    expected: e.compiled as usize,
                    actual: None,
                    detail: err.to_string(),
                });
            }
            (res, _) => missing.push(Mismatch {
                name: e.name,
                struct_name: e.enum_name,
                expected: e.compiled as usize,
                actual: None,
                detail: match res {
                    Err(err) => err.to_string(),
                    Ok(_) => {
                        "no BTF_OFFSETS slot for this enum (ENUM_SLOT_TABLE out of sync)".into()
                    }
                },
            }),
        }
    }
    if missing.is_empty() {
        ResolveOutcome::Resolved(ResolvedOffsets {
            values,
            drifted,
            absent,
            modules_not_loaded,
        })
    } else {
        ResolveOutcome::Refuse(RefuseReason::Drift(missing))
    }
}

/// tracefs roots tried in order for the tracepoint `format` files.
pub const TRACEFS_ROOTS: &[&str] = &["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];

/// External audit NN-AUD-098: where the fixed part of a tracepoint record
/// may end at most. A resolved field must end within it; past it the
/// program would read bytes outside the record. The records the sensors
/// read end by byte 64 on every kernel seen (5.14 el9 to 6.8); this
/// leaves eight times that.
pub const TRACEPOINT_RECORD_MAX: u32 = 512;

/// Largest `format` file read (they are a few hundred bytes).
const FORMAT_FILE_MAX: u64 = 64 * 1024;

/// Outcome of [`resolve_tracepoint_fields`]: one `(slot, offset)` per
/// [`TRACEPOINT_FIELDS`] entry (the compiled value when tracefs could not
/// answer), plus what differed and what could not be read.
#[derive(Debug, Default, Clone)]
pub struct TracepointOffsets {
    pub values: Vec<(u32, u32)>,
    /// `(name, compiled, runtime)` for fields whose offset differs.
    pub drifted: Vec<(&'static str, u32, u32)>,
    /// `(name, reason)` for fields left at the compiled value: not found,
    /// or found and rejected (external audit NN-AUD-098).
    pub unresolved: Vec<(&'static str, String)>,
    /// External audit NN-AUD-098: `(root, reason)` for roots not used
    /// because they are not tracefs.
    pub skipped_roots: Vec<(String, String)>,
}

impl TracepointOffsets {
    /// External audit NN-AUD-098: the detail of the signed
    /// `subsystem_degraded` entry when a field kept its compiled value
    /// (`None` when every field was resolved).
    pub fn degraded_detail(&self) -> Option<String> {
        const MAX: usize = 2048;
        if self.unresolved.is_empty() {
            return None;
        }
        let fields: Vec<String> = self
            .unresolved
            .iter()
            .map(|(name, why)| format!("{name} ({why})"))
            .collect();
        let mut detail = format!(
            "tracepoint field offsets: {} of {} on the compiled value, the build kernel's \
             layout — on another layout the tracepoint sensors read wrong bytes: {}",
            self.unresolved.len(),
            self.values.len(),
            fields.join("; ")
        );
        if !self.skipped_roots.is_empty() {
            let roots: Vec<String> = self
                .skipped_roots
                .iter()
                .map(|(root, why)| format!("{root} ({why})"))
                .collect();
            detail.push_str(&format!("; tracefs roots not used: {}", roots.join(", ")));
        }
        if detail.len() > MAX {
            let mut cut = MAX;
            while !detail.is_char_boundary(cut) {
                cut -= 1;
            }
            detail.truncate(cut);
            detail.push('…');
        }
        Some(detail)
    }
}

/// Resolve the tracepoint field offsets the eBPF programs read with
/// `read_at` from the running kernel's tracefs `format` files. The
/// common tracepoint header is not stable across vendor kernels (RHEL 9
/// inserts `common_preempt_lazy_count`, shifting every field by 4), so a
/// compiled-in offset silently reads the wrong bytes there — the exec
/// sensor then reports an empty filename. A field that cannot be read
/// keeps its compiled value and is reported in `unresolved` (the caller
/// warns and attests it; the rules treat an empty filename as "unknown",
/// never as "non-standard").
///
/// External audit NN-AUD-098: the files are root-writable input only if
/// they are not tracefs — a tmpfs mounted over `/sys/kernel/tracing`, or a
/// file bind-mounted over one `format`, would choose where the sensors
/// read. A root and each file are used only on tracefs.
pub fn resolve_tracepoint_fields() -> TracepointOffsets {
    resolve_tracepoint_fields_from(TRACEFS_ROOTS, crate::fs_type::TRACEFS_MAGIC)
}

/// [`resolve_tracepoint_fields`] over explicit roots, whose files must be
/// on a filesystem of type `fs_magic` (tests pass their temporary
/// directory's type).
pub fn resolve_tracepoint_fields_from(roots: &[&str], fs_magic: u64) -> TracepointOffsets {
    use common::btf_offsets::{TRACEPOINT_FIELDS, TRACEPOINT_SLOT_TABLE};
    let mut out = TracepointOffsets::default();
    // External audit NN-AUD-098: a root that is not tracefs is not used.
    let mut usable: Vec<&str> = Vec::new();
    let mut root_errors: Vec<String> = Vec::new();
    for root in roots {
        match crate::fs_type::magic_of_path(std::path::Path::new(root)) {
            Some(m) if m == fs_magic => usable.push(root),
            Some(m) => {
                let why = format!("filesystem type {m:#x}, not tracefs");
                root_errors.push(format!("{root}: {why}"));
                out.skipped_roots.push((root.to_string(), why));
            }
            None => root_errors.push(format!("{root}: unavailable")),
        }
    }
    for (spec, (name, slot)) in TRACEPOINT_FIELDS.iter().zip(TRACEPOINT_SLOT_TABLE) {
        debug_assert_eq!(spec.name, *name);
        let mut found: Option<u32> = None;
        let mut reasons: Vec<String> = root_errors.clone();
        let events: &[&str] = if spec.alt_event.is_empty() {
            &[spec.event]
        } else {
            &[spec.event, spec.alt_event]
        };
        'roots: for root in &usable {
            for event in events {
                let path = format!("{root}/events/{}/{event}/format", spec.category);
                let text = match read_format_file(&path, fs_magic) {
                    Ok(text) => text,
                    Err(e) => {
                        reasons.push(format!("{path}: {e}"));
                        continue;
                    }
                };
                // External audit NN-AUD-098: a format without the field
                // tries the next event (`alt_event`), it does not end the
                // search; a field that fails the checks is not used.
                match parse_format_field(&text, spec.field) {
                    Some(field) => match check_format_field(&text, spec, field) {
                        Ok(off) => {
                            found = Some(off);
                            break 'roots;
                        }
                        Err(why) => reasons.push(format!("{path}: {why}")),
                    },
                    None => reasons.push(format!("{path}: field `{}` not in format", spec.field)),
                }
            }
        }
        match found {
            Some(off) => {
                if off != spec.compiled {
                    out.drifted.push((spec.name, spec.compiled, off));
                }
                out.values.push((*slot, off));
            }
            None => {
                if reasons.is_empty() {
                    reasons.push("no tracefs root".to_string());
                }
                out.unresolved.push((spec.name, reasons.join("; ")));
                out.values.push((*slot, spec.compiled));
            }
        }
    }
    out
}

/// A tracefs `format` file, read only if it is on a filesystem of type
/// `fs_magic` (external audit NN-AUD-098: checked on the open file, so a
/// file mounted over one path is caught whatever its root is).
fn read_format_file(path: &str, fs_magic: u64) -> std::io::Result<String> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    match crate::fs_type::magic_of_file(&file) {
        Some(m) if m == fs_magic => {}
        Some(m) => {
            return Err(std::io::Error::other(format!(
                "filesystem type {m:#x}, not tracefs"
            )))
        }
        None => return Err(std::io::Error::last_os_error()),
    }
    let mut text = String::new();
    file.take(FORMAT_FILE_MAX).read_to_string(&mut text)?;
    Ok(text)
}

/// One `field:` line of a tracefs `format` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatField<'a> {
    pub name: &'a str,
    pub offset: Option<u32>,
    pub size: Option<u32>,
}

/// The `field:` lines of a tracefs `format` file body. Field lines look
/// like `\tfield:__data_loc char[] filename;\toffset:8;\tsize:4;\tsigned:1;`;
/// the name is the last token of the declaration, with any `[…]` stripped
/// (`char comm[TASK_COMM_LEN]`).
pub fn format_fields(text: &str) -> impl Iterator<Item = FormatField<'_>> {
    text.lines().filter_map(|line| {
        let rest = line.trim().strip_prefix("field:")?;
        let mut parts = rest.split(';');
        let decl = parts.next()?.trim();
        let name = decl
            .rsplit(|c: char| c.is_whitespace() || c == '*')
            .next()?;
        let name = name.split('[').next()?;
        let (mut offset, mut size) = (None, None);
        for part in parts {
            let part = part.trim();
            if let Some(v) = part.strip_prefix("offset:") {
                offset = offset.or(Some(v.trim().parse::<u32>().ok()));
            } else if let Some(v) = part.strip_prefix("size:") {
                size = size.or(Some(v.trim().parse::<u32>().ok()));
            }
        }
        Some(FormatField {
            name,
            offset: offset.flatten(),
            size: size.flatten(),
        })
    })
}

/// The first `field:` line named `field`.
pub fn parse_format_field<'a>(text: &'a str, field: &str) -> Option<FormatField<'a>> {
    format_fields(text).find(|f| f.name == field)
}

/// `offset:` of `field` in a tracefs `format` file body.
pub fn parse_format_field_offset(text: &str, field: &str) -> Option<u32> {
    parse_format_field(text, field)?.offset
}

/// External audit NN-AUD-098: the offset of `field` if it is plausible —
/// the width the program reads, past the common header (the `common_*`
/// fields), and ending within [`TRACEPOINT_RECORD_MAX`].
fn check_format_field(
    text: &str,
    spec: &common::btf_offsets::TracepointFieldSpec,
    field: FormatField<'_>,
) -> Result<u32, String> {
    let Some(offset) = field.offset else {
        return Err(format!("field `{}` has no offset", spec.field));
    };
    let Some(size) = field.size else {
        return Err(format!("field `{}` has no size", spec.field));
    };
    if size != spec.size {
        return Err(format!(
            "field `{}` is {size} bytes wide, the sensor reads {}",
            spec.field, spec.size
        ));
    }
    if offset
        .checked_add(size)
        .is_none_or(|end| end > TRACEPOINT_RECORD_MAX)
    {
        return Err(format!(
            "field `{}` at {offset} (+{size}) ends past the record (at most {TRACEPOINT_RECORD_MAX} \
             bytes)",
            spec.field
        ));
    }
    let header_end = format_fields(text)
        .filter(|f| f.name.starts_with("common_"))
        .filter_map(|f| f.offset?.checked_add(f.size?))
        .max()
        .unwrap_or(0);
    if offset < header_end {
        return Err(format!(
            "field `{}` at {offset} lies inside the common header (ends at {header_end})",
            spec.field
        ));
    }
    Ok(offset)
}

/// Fuzzing entry (see `crate::fuzz_api`): parse + resolve, never panic.
#[doc(hidden)]
pub fn fuzz_parse_and_resolve(data: &[u8]) -> bool {
    match Btf::parse(data) {
        Ok(btf) => {
            let _ = resolve_with(&btf, REVALIDATE, ENUM_VALUES, &|_| None);
            let _ = revalidate_with(&btf, REVALIDATE);
            true
        }
        Err(_) => false,
    }
}

static RESOLVED: OnceLock<ResolvedOffsets> = OnceLock::new();

/// Publish the boot-time resolution for [`arm_btf_offsets`]. Idempotent;
/// the first value wins.
pub fn publish_resolved(r: ResolvedOffsets) {
    let _ = RESOLVED.set(r);
}

/// Resolution published at boot, if any.
pub fn resolved() -> Option<&'static ResolvedOffsets> {
    RESOLVED.get()
}

/// Write the published offsets into the loaded object's `BTF_OFFSETS`
/// map and arm it (slot 0 = magic). Must run after `EbpfLoader::load`
/// and BEFORE any program is attached. With nothing published (no BTF
/// on this kernel) the map stays unarmed and the programs use their
/// compiled-in constants, exactly as before runtime offsets existed.
pub fn arm_btf_offsets(ebpf: &mut aya::Ebpf) -> anyhow::Result<usize> {
    use anyhow::Context;
    let Some(r) = resolved() else {
        return Ok(0);
    };
    let map = ebpf
        .map_mut("BTF_OFFSETS")
        .context("BTF_OFFSETS map missing from the eBPF object")?;
    let mut arr: aya::maps::Array<_, u32> =
        aya::maps::Array::try_from(map).context("BTF_OFFSETS is not an Array<u32>")?;
    for (slot, value) in &r.values {
        arr.set(*slot, *value, 0)
            .with_context(|| format!("BTF_OFFSETS slot {slot} write"))?;
    }
    arr.set(0, BTF_OFFSETS_MAGIC, 0)
        .context("BTF_OFFSETS magic write")?;
    Ok(r.values.len())
}

/// `BPF_MAP_FREEZE` command number (uapi, stable).
const BPF_MAP_FREEZE_CMD: libc::c_long = 22;

/// External audit EBPF-004: once armed, `BTF_OFFSETS` is frozen — no
/// process, root included, can write it again (`BPF_MAP_FREEZE`); the
/// programs still read it. Nothing writes it after the arming, and a
/// poisoned table would blind every hook that reads a kernel structure
/// through it. Frozen unarmed too: the compiled-in offsets then apply for
/// good.
pub fn freeze_btf_offsets(ebpf: &aya::Ebpf) -> anyhow::Result<()> {
    use anyhow::Context;
    use std::os::fd::{AsFd, AsRawFd};
    let map = ebpf
        .map("BTF_OFFSETS")
        .context("BTF_OFFSETS map missing from the eBPF object")?;
    let aya::maps::Map::Array(data) = map else {
        anyhow::bail!("BTF_OFFSETS is not an array map");
    };
    #[repr(C)]
    struct FreezeAttr {
        map_fd: u32,
    }
    let attr = FreezeAttr {
        map_fd: data.fd().as_fd().as_raw_fd() as u32,
    };
    // SAFETY: plain syscall with a valid, fully initialised attr struct and
    // its exact size; the fd is borrowed from the live map.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_FREEZE_CMD,
            &attr as *const FreezeAttr as *const libc::c_void,
            std::mem::size_of::<FreezeAttr>() as u32,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error()).context("BPF_MAP_FREEZE on BTF_OFFSETS");
    }
    Ok(())
}

/// Core comparison, split out so tests can drive it with synthetic BTF
/// + specs (no real `/sys/kernel/btf/vmlinux` needed).
fn revalidate_with(btf: &Btf, specs: &[OffsetSpec]) -> RevalidateOutcome {
    let mut mismatches = Vec::new();
    // A module's structs are not in vmlinux; `resolve_offsets` reads them
    // from the module's BTF.
    let in_vmlinux = |s: &&OffsetSpec| {
        !BTF_MODULE_STRUCTS
            .iter()
            .any(|(st, _)| *st == s.struct_name)
    };
    let specs: Vec<&OffsetSpec> = specs.iter().filter(in_vmlinux).collect();
    for spec in &specs {
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
    /// A module's BTF was needed but is missing or unparseable.
    ModuleBtf(String),
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
            ResolveError::ModuleBtf(s) => write!(f, "module BTF: {s}"),
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
    /// A (32-bit) enum: `(name_off, value)` per enumerator — looked up
    /// by name for the enum-value relocations (multi-kernel, level 2).
    Enum { values: Vec<(u32, i32)> },
    /// Anything we don't navigate into (int, ptr, array, …). A
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
        Self::parse_on(data, None)
    }

    /// Parse `data`, or — with `base` — a module's split BTF on top of the
    /// kernel's: its type ids start at the base's count and its string
    /// offsets at the base's string-section length, so names and member
    /// types may live in the base. The result holds only the module's own
    /// types and strings; [`SplitBtf`] joins the two.
    fn parse_on(data: &[u8], base: Option<&Btf>) -> Result<Btf, ParseError> {
        let (first_id, first_str) =
            base.map_or((0, 0), |b| (b.types.len() as u32, b.strings.len() as u32));
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
        let name_of = |off: u32| -> Option<String> {
            if off < first_str {
                base.and_then(|b| name_at(&b.strings, off).ok())
                    .map(str::to_string)
            } else {
                name_at(&strings, off - first_str).ok().map(str::to_string)
            }
        };

        // id 0 is void; real types are 1-based. A split BTF's first type
        // continues the base's ids.
        let mut types = if base.is_some() {
            Vec::new()
        } else {
            vec![Ty::Opaque]
        };
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
            let id = first_id + types.len() as u32;

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
                        if let Some(nm) = name_of(name_off) {
                            // First definition wins (BTF defines each
                            // struct once; FWDs are a distinct kind).
                            name_to_id.entry(nm).or_insert(id);
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
                KIND_ENUM => {
                    let base0 = p;
                    if base0 + vlen * 8 > data.len() {
                        return Err(ParseError(format!("enum members OOB in type {id}")));
                    }
                    let mut values = Vec::with_capacity(vlen);
                    for i in 0..vlen {
                        let base = base0 + i * 8;
                        values.push((r.u32(base)?, r.u32(base + 4)? as i32));
                    }
                    p += vlen * 8;
                    if name_off != 0 {
                        if let Some(nm) = name_of(name_off) {
                            name_to_id.entry(nm).or_insert(id);
                        }
                    }
                    types.push(Ty::Enum { values });
                }
                KIND_FUNC_PROTO => {
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
                    // 40 target structs are parseable — at which point
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

    /// Value of enumerator `value_name` in the named enum `enum_name`.
    fn resolve_enum(&self, enum_name: &str, value_name: &str) -> Result<i32, ResolveError> {
        let id = *self
            .name_to_id
            .get(enum_name)
            .ok_or_else(|| ResolveError::StructNotFound(enum_name.to_string()))?;
        let Some(Ty::Enum { values }) = self.types.get(id as usize) else {
            return Err(ResolveError::StructNotFound(format!(
                "{enum_name} is not an enum"
            )));
        };
        for (name_off, v) in values {
            if name_at(&self.strings, *name_off)
                .map(|n| n == value_name)
                .unwrap_or(false)
            {
                return Ok(*v);
            }
        }
        Err(ResolveError::FieldNotFound(format!(
            "{enum_name}.{value_name}"
        )))
    }
}

/// Type and name lookups the offset navigation needs: a plain BTF, or a
/// module's split BTF joined to the kernel's ([`SplitBtf`]).
trait TypeTable {
    fn ty(&self, id: u32) -> Option<&Ty>;
    fn name(&self, off: u32) -> Result<&str, ParseError>;
    fn id_of(&self, name: &str) -> Option<u32>;

    /// Follow `Forward` (typedef/cv-qual) chains to the underlying
    /// struct/union id. Returns `None` if the chain doesn't end in a
    /// composite (e.g. it's a pointer/int).
    fn resolve_navigable(&self, mut id: u32) -> Option<u32> {
        for _ in 0..64 {
            match self.ty(id)? {
                Ty::Composite { .. } => return Some(id),
                Ty::Forward { type_id } => id = *type_id,
                Ty::Enum { .. } | Ty::Opaque => return None,
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
        let Ty::Composite { members } = self.ty(struct_id)? else {
            return None;
        };
        for m in members {
            let mname = self.name(m.name_off).unwrap_or("");
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
        let id = self
            .id_of(struct_name)
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

impl TypeTable for Btf {
    fn ty(&self, id: u32) -> Option<&Ty> {
        self.types.get(id as usize)
    }
    fn name(&self, off: u32) -> Result<&str, ParseError> {
        name_at(&self.strings, off)
    }
    fn id_of(&self, name: &str) -> Option<u32> {
        self.name_to_id.get(name).copied()
    }
}

/// A kernel module's BTF (`/sys/kernel/btf/<module>`) on top of the
/// kernel's: ids below `first_id` and string offsets below `first_str`
/// are the base's. Review 55: `btrfs_inode` and `btrfs_root` live in the
/// btrfs module's BTF when btrfs is not built in.
struct SplitBtf<'a> {
    base: &'a Btf,
    own: Btf,
    first_id: u32,
    first_str: u32,
}

impl<'a> SplitBtf<'a> {
    fn parse(base: &'a Btf, data: &[u8]) -> Result<Self, ParseError> {
        Ok(SplitBtf {
            base,
            own: Btf::parse_on(data, Some(base))?,
            first_id: base.types.len() as u32,
            first_str: base.strings.len() as u32,
        })
    }
}

impl TypeTable for SplitBtf<'_> {
    fn ty(&self, id: u32) -> Option<&Ty> {
        if id < self.first_id {
            self.base.ty(id)
        } else {
            self.own.types.get((id - self.first_id) as usize)
        }
    }
    fn name(&self, off: u32) -> Result<&str, ParseError> {
        if off < self.first_str {
            self.base.name(off)
        } else {
            name_at(&self.own.strings, off - self.first_str)
        }
    }
    fn id_of(&self, name: &str) -> Option<u32> {
        self.own
            .name_to_id
            .get(name)
            .copied()
            .or_else(|| self.base.id_of(name))
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

    const UPSTREAM_EXEC_FORMAT: &str = "name: sched_process_exec\nID: 310\nformat:\n\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\n\tfield:__data_loc char[] filename;\toffset:8;\tsize:4;\tsigned:1;\n\tfield:pid_t pid;\toffset:12;\tsize:4;\tsigned:1;\n\tfield:pid_t old_pid;\toffset:16;\tsize:4;\tsigned:1;\n";
    const RHEL9_EXEC_FORMAT: &str = "name: sched_process_exec\nID: 295\nformat:\n\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\tfield:unsigned char common_preempt_lazy_count;\toffset:8;\tsize:1;\tsigned:0;\n\n\tfield:__data_loc char[] filename;\toffset:12;\tsize:4;\tsigned:1;\n\tfield:pid_t pid;\toffset:16;\tsize:4;\tsigned:1;\n\tfield:pid_t old_pid;\toffset:20;\tsize:4;\tsigned:1;\n";
    const RHEL9_OPENAT_FORMAT: &str = "format:\n\tfield:unsigned char common_preempt_lazy_count;\toffset:8;\tsize:1;\tsigned:0;\n\tfield:int __syscall_nr;\toffset:12;\tsize:4;\tsigned:1;\n\tfield:int dfd;\toffset:16;\tsize:8;\tsigned:0;\n\tfield:const char * filename;\toffset:24;\tsize:8;\tsigned:0;\n\tfield:int flags;\toffset:32;\tsize:8;\tsigned:0;\n\tfield:umode_t mode;\toffset:40;\tsize:8;\tsigned:0;\n";

    #[test]
    fn format_parser_reads_upstream_and_rhel9_layouts() {
        assert_eq!(
            parse_format_field_offset(UPSTREAM_EXEC_FORMAT, "filename"),
            Some(8)
        );
        assert_eq!(
            parse_format_field_offset(RHEL9_EXEC_FORMAT, "filename"),
            Some(12)
        );
        assert_eq!(
            parse_format_field_offset(RHEL9_EXEC_FORMAT, "old_pid"),
            Some(20)
        );
        // pointer declarations (`const char * filename`) and array names
        assert_eq!(
            parse_format_field_offset(RHEL9_OPENAT_FORMAT, "filename"),
            Some(24)
        );
        assert_eq!(
            parse_format_field_offset(RHEL9_OPENAT_FORMAT, "flags"),
            Some(32)
        );
        assert_eq!(
            parse_format_field_offset(
                "\tfield:char comm[TASK_COMM_LEN];\toffset:12;\tsize:16;\tsigned:1;\n",
                "comm"
            ),
            Some(12)
        );
        assert_eq!(parse_format_field_offset(RHEL9_EXEC_FORMAT, "nope"), None);
    }

    /// The io_uring submit tracepoint is `io_uring_submit_sqe` on 5.15 /
    /// 6.1 and `io_uring_submit_req` on 6.8 / RHEL 9: the resolver tries
    /// the alternative name and places `opcode` wherever that kernel has it.
    #[test]
    fn io_uring_submit_resolves_through_the_alternative_event_name() {
        use common::btf_offsets::slot;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let sqe = root.join("events/io_uring/io_uring_submit_sqe");
        fs::create_dir_all(&sqe).unwrap();
        fs::write(sqe.join("format"), "format:\n\tfield:void * ctx;\toffset:8;\tsize:8;\tsigned:0;\n\tfield:void * req;\toffset:16;\tsize:8;\tsigned:0;\n\tfield:u8 opcode;\toffset:24;\tsize:1;\tsigned:0;\n\tfield:u64 user_data;\toffset:32;\tsize:8;\tsigned:0;\n\tfield:u32 flags;\toffset:40;\tsize:4;\tsigned:0;\n\tfield:bool force_nonblock;\toffset:44;\tsize:1;\tsigned:0;\n\tfield:bool sq_thread;\toffset:45;\tsize:1;\tsigned:0;\n").unwrap();
        let r = resolve_in(root);
        assert!(r
            .values
            .contains(&(slot::TP_IOURING_SUBMIT_OPCODE_OFFSET, 24)));
        assert!(r
            .values
            .contains(&(slot::TP_IOURING_SUBMIT_SQ_THREAD_OFFSET, 45)));
        assert!(r
            .drifted
            .iter()
            .any(|(n, _, rt)| *n == "TP_IOURING_SUBMIT_OPCODE_OFFSET" && *rt == 24));
    }

    /// A synthetic tracefs tree with the RHEL 9 layout: the exec filename
    /// slot drifts to 12, the syscall fields stay put, and a missing
    /// event falls back to the compiled value and is reported.
    #[test]
    fn tracepoint_fields_resolve_from_tracefs_tree() {
        use common::btf_offsets::{slot, TP_SCHED_EXEC_FILENAME_OFFSET};
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let exec = root.join("events/sched/sched_process_exec");
        fs::create_dir_all(&exec).unwrap();
        fs::write(exec.join("format"), RHEL9_EXEC_FORMAT).unwrap();
        let openat = root.join("events/syscalls/sys_enter_openat");
        fs::create_dir_all(&openat).unwrap();
        fs::write(openat.join("format"), RHEL9_OPENAT_FORMAT).unwrap();
        // sys_enter_execve deliberately absent
        let r = resolve_in(root);
        assert_eq!(r.values.len(), common::btf_offsets::TRACEPOINT_FIELDS.len());
        assert!(r
            .values
            .contains(&(slot::TP_SCHED_EXEC_FILENAME_OFFSET, 12)));
        assert!(r
            .values
            .contains(&(slot::TP_SYS_ENTER_OPENAT_FLAGS_OFFSET, 32)));
        assert_eq!(
            r.drifted,
            vec![(
                "TP_SCHED_EXEC_FILENAME_OFFSET",
                TP_SCHED_EXEC_FILENAME_OFFSET as u32,
                12
            )]
        );
        // sys_enter_execve and the five io_uring fields are absent from the tree
        assert_eq!(r.unresolved.len(), 6);
        assert_eq!(r.unresolved[0].0, "TP_SYS_ENTER_EXECVE_FILENAME_OFFSET");
        assert!(r
            .values
            .contains(&(slot::TP_SYS_ENTER_EXECVE_FILENAME_OFFSET, 16)));
        // no readable root at all: every slot keeps its compiled value
        let none = resolve_tracepoint_fields_from(
            &["/nonexistent/tracefs"],
            crate::fs_type::TRACEFS_MAGIC,
        );
        assert_eq!(none.unresolved.len(), none.values.len());
        assert!(none.drifted.is_empty());
    }

    /// [`resolve_tracepoint_fields_from`] over a temporary tree, accepted
    /// as "tracefs" by its own filesystem type.
    fn resolve_in(root: &std::path::Path) -> TracepointOffsets {
        let magic = crate::fs_type::magic_of_path(root).expect("statfs on a temp dir");
        resolve_tracepoint_fields_from(&[root.to_str().unwrap()], magic)
    }

    fn write_format(root: &std::path::Path, category: &str, event: &str, body: &str) {
        let dir = root.join("events").join(category).join(event);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("format"), body).unwrap();
    }

    const SQE_FORMAT: &str = "format:\n\tfield:void * ctx;\toffset:8;\tsize:8;\tsigned:0;\n\tfield:void * req;\toffset:16;\tsize:8;\tsigned:0;\n\tfield:u8 opcode;\toffset:24;\tsize:1;\tsigned:0;\n\tfield:u64 user_data;\toffset:32;\tsize:8;\tsigned:0;\n\tfield:u32 flags;\toffset:40;\tsize:4;\tsigned:0;\n\tfield:bool force_nonblock;\toffset:44;\tsize:1;\tsigned:0;\n\tfield:bool sq_thread;\toffset:45;\tsize:1;\tsigned:0;\n";

    /// External audit NN-AUD-098 (a): the primary event exists but lacks
    /// the field — the alternative event is still tried. Before the fix
    /// the search ended there and the compiled 32 / 48 stayed.
    #[test]
    fn alt_event_tried_when_primary_lacks_field() {
        use common::btf_offsets::slot;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_format(
            root,
            "io_uring",
            "io_uring_submit_req",
            "format:\n\tfield:void * ctx;\toffset:8;\tsize:8;\tsigned:0;\n\tfield:void * req;\toffset:16;\tsize:8;\tsigned:0;\n",
        );
        write_format(root, "io_uring", "io_uring_submit_sqe", SQE_FORMAT);
        let r = resolve_in(root);
        assert!(
            r.values
                .contains(&(slot::TP_IOURING_SUBMIT_OPCODE_OFFSET, 24)),
            "{r:?}"
        );
        assert!(r
            .values
            .contains(&(slot::TP_IOURING_SUBMIT_SQ_THREAD_OFFSET, 45)));
        assert!(!r
            .unresolved
            .iter()
            .any(|(n, _)| n.starts_with("TP_IOURING_SUBMIT")));
    }

    /// External audit NN-AUD-098 (b, d): a root that is not tracefs (here a
    /// temporary directory, with a well-formed tree in it) is not read;
    /// every field keeps its compiled value and the reason is attested.
    #[test]
    fn non_tracefs_root_is_skipped() {
        use common::btf_offsets::{slot, TRACEPOINT_FIELDS};
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_format(root, "sched", "sched_process_exec", RHEL9_EXEC_FORMAT);
        assert_ne!(
            crate::fs_type::magic_of_path(root),
            Some(crate::fs_type::TRACEFS_MAGIC)
        );
        let r = resolve_tracepoint_fields_from(
            &[root.to_str().unwrap()],
            crate::fs_type::TRACEFS_MAGIC,
        );
        assert!(
            r.values.contains(&(slot::TP_SCHED_EXEC_FILENAME_OFFSET, 8)),
            "the compiled offset, not the tree's 12: {r:?}"
        );
        assert!(r.drifted.is_empty());
        assert_eq!(r.unresolved.len(), TRACEPOINT_FIELDS.len());
        assert_eq!(r.skipped_roots.len(), 1);
        assert_eq!(r.skipped_roots[0].0, root.to_str().unwrap());
        assert!(r.skipped_roots[0].1.contains("not tracefs"));
        let detail = r.degraded_detail().expect("attested");
        assert!(detail.contains("9 of 9 on the compiled value"), "{detail}");
        assert!(detail.contains("TP_SCHED_EXEC_FILENAME_OFFSET"), "{detail}");
        assert!(
            detail.contains(&format!("tracefs roots not used: {}", root.display())),
            "{detail}"
        );
        // the same tree accepted as the expected type: resolved, nothing to attest
        let ok = resolve_in(root);
        assert!(ok
            .values
            .contains(&(slot::TP_SCHED_EXEC_FILENAME_OFFSET, 12)));
        assert!(ok.skipped_roots.is_empty());
    }

    /// External audit NN-AUD-098 (b): the check is made on each open file,
    /// so a `format` on another filesystem under an accepted root (a bind
    /// mount in the field; a directory link to `/dev/shm` here) is refused.
    #[test]
    fn format_file_on_another_filesystem_is_rejected() {
        use common::btf_offsets::slot;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let Ok(shm) = tempfile::tempdir_in("/dev/shm") else {
            eprintln!("no /dev/shm; skipping");
            return;
        };
        let (Some(here), Some(there)) = (
            crate::fs_type::magic_of_path(root),
            crate::fs_type::magic_of_path(shm.path()),
        ) else {
            return;
        };
        if here == there {
            eprintln!("temp dir and /dev/shm on the same filesystem type; skipping");
            return;
        }
        write_format(shm.path(), "sched", "sched_process_exec", RHEL9_EXEC_FORMAT);
        std::os::unix::fs::symlink(shm.path().join("events"), root.join("events")).unwrap();
        let r = resolve_in(root);
        assert!(r.values.contains(&(slot::TP_SCHED_EXEC_FILENAME_OFFSET, 8)));
        let (_, why) = r
            .unresolved
            .iter()
            .find(|(n, _)| *n == "TP_SCHED_EXEC_FILENAME_OFFSET")
            .expect("unresolved");
        assert!(why.contains("not tracefs"), "{why}");
    }

    /// External audit NN-AUD-098 (c): an offset past the record, a width
    /// other than the one the program reads, or an offset inside the
    /// common header is not used — the compiled value stays and the
    /// reason is reported. Before the fix each was written to the map.
    #[test]
    fn offset_beyond_record_is_rejected() {
        use common::btf_offsets::slot;
        let header = "format:\n\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n";
        let cases = [
            (
                "\tfield:__data_loc char[] filename;\toffset:4096;\tsize:4;\tsigned:1;\n",
                "ends past the record",
            ),
            (
                "\tfield:__data_loc char[] filename;\toffset:509;\tsize:4;\tsigned:1;\n",
                "ends past the record",
            ),
            (
                "\tfield:__data_loc char[] filename;\toffset:4294967295;\tsize:4;\tsigned:1;\n",
                "ends past the record",
            ),
            (
                "\tfield:char * filename;\toffset:16;\tsize:8;\tsigned:0;\n",
                "8 bytes wide, the sensor reads 4",
            ),
            (
                "\tfield:__data_loc char[] filename;\toffset:16;\tsigned:1;\n",
                "has no size",
            ),
            (
                "\tfield:__data_loc char[] filename;\toffset:4;\tsize:4;\tsigned:1;\n",
                "inside the common header (ends at 8)",
            ),
        ];
        for (line, why) in cases {
            let dir = tempfile::tempdir().unwrap();
            write_format(
                dir.path(),
                "sched",
                "sched_process_exec",
                &format!("{header}\n{line}"),
            );
            let r = resolve_in(dir.path());
            assert!(
                r.values.contains(&(slot::TP_SCHED_EXEC_FILENAME_OFFSET, 8)),
                "{line}: {r:?}"
            );
            assert!(r.drifted.is_empty(), "{line}");
            let (_, reason) = r
                .unresolved
                .iter()
                .find(|(n, _)| *n == "TP_SCHED_EXEC_FILENAME_OFFSET")
                .expect("rejected");
            assert!(reason.contains(why), "{line}: {reason}");
        }
        // the record's last plausible bytes are still accepted
        let dir = tempfile::tempdir().unwrap();
        write_format(
            dir.path(),
            "sched",
            "sched_process_exec",
            &format!(
                "{header}\n\tfield:__data_loc char[] filename;\toffset:508;\tsize:4;\tsigned:1;\n"
            ),
        );
        assert!(resolve_in(dir.path())
            .values
            .contains(&(slot::TP_SCHED_EXEC_FILENAME_OFFSET, 508)));
    }

    /// Stock layouts pass the checks of NN-AUD-098 unchanged: upstream 6.8
    /// and RHEL 9 exec, RHEL 9 openat, 5.15 io_uring submit.
    #[test]
    fn stock_layouts_pass_the_plausibility_checks() {
        use common::btf_offsets::slot;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_format(root, "sched", "sched_process_exec", UPSTREAM_EXEC_FORMAT);
        write_format(root, "syscalls", "sys_enter_openat", RHEL9_OPENAT_FORMAT);
        write_format(root, "io_uring", "io_uring_submit_sqe", SQE_FORMAT);
        let r = resolve_in(root);
        for (s, v) in [
            (slot::TP_SCHED_EXEC_FILENAME_OFFSET, 8),
            (slot::TP_SYS_ENTER_OPENAT_FILENAME_OFFSET, 24),
            (slot::TP_SYS_ENTER_OPENAT_FLAGS_OFFSET, 32),
            (slot::TP_IOURING_SUBMIT_OPCODE_OFFSET, 24),
        ] {
            assert!(r.values.contains(&(s, v)), "slot {s}: {r:?}");
        }
        assert_eq!(
            parse_format_field(RHEL9_EXEC_FORMAT, "filename"),
            Some(FormatField {
                name: "filename",
                offset: Some(12),
                size: Some(4)
            })
        );
    }

    /// Minimal BTF encoder for hermetic, kernel-independent tests.
    /// Lays out `[header(24)][types][strings]`; ids are 1-based to
    /// match the parser's void-at-0 convention.
    struct BtfBuilder {
        types: Vec<u8>,
        strings: Vec<u8>,
        next_id: u32,
        /// String offset of `strings[0]`: 0, or a split BTF's base length.
        str_base: u32,
    }

    impl BtfBuilder {
        fn new() -> Self {
            // strings[0] = NUL ⇒ name_off 0 is the empty (anonymous) name.
            BtfBuilder {
                types: Vec::new(),
                strings: vec![0],
                next_id: 1,
                str_base: 0,
            }
        }

        /// A module's split BTF over a base of `base_types` types (void
        /// included) and a `base_str_len`-byte string section.
        fn split_on(base_types: u32, base_str_len: u32) -> Self {
            BtfBuilder {
                types: Vec::new(),
                strings: Vec::new(),
                next_id: base_types,
                str_base: base_str_len,
            }
        }

        fn str(&mut self, s: &str) -> u32 {
            let off = self.str_base + self.strings.len() as u32;
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

    /// Build a fixture exercising every navigation path the real 40 use:
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
            OffsetSpec {
                name: "OUTER_A",
                struct_name: "outer",
                field_path: &["a"],
                expected: 0,
                alt_paths: &[],
                optional: false,
            },
            OffsetSpec {
                name: "INNER_X",
                struct_name: "inner",
                field_path: &["x"],
                expected: 8,
                alt_paths: &[],
                optional: false,
            },
            OffsetSpec {
                name: "EMB_X",
                struct_name: "outer",
                field_path: &["emb", "x"],
                expected: 24,
                alt_paths: &[],
                optional: false,
            },
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
            OffsetSpec {
                name: "OUTER_A",
                struct_name: "outer",
                field_path: &["a"],
                expected: 0,
                alt_paths: &[],
                optional: false,
            }, // ok
            OffsetSpec {
                name: "INNER_X_WRONG",
                struct_name: "inner",
                field_path: &["x"],
                expected: 99,
                alt_paths: &[],
                optional: false,
            }, // drift
            OffsetSpec {
                name: "GHOST",
                struct_name: "ghost",
                field_path: &["x"],
                expected: 0,
                alt_paths: &[],
                optional: false,
            }, // missing
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

    /// VM-only: derive ALL compiled-in offsets against the *running*
    /// kernel's real BTF and assert they match.
    /// `#[ignore]`d so it never runs on a dev box whose kernel differs
    /// from the supported 6.8.x (where the offsets legitimately
    /// differ); run on the target with
    /// `cargo test -p northnarrow-agent --lib btf_revalidate -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn revalidate_real_kernel_btf_all_40_match() {
        // Since multi-kernel level 1 drift is allowed: every offset and
        // enumerator must RESOLVE on the running kernel (values go into
        // the BTF_OFFSETS map); only a missing field is a failure.
        match resolve_offsets() {
            ResolveOutcome::Resolved(r) => {
                let expected = REVALIDATE.len() + ENUM_VALUES.len();
                assert_eq!(
                    r.values.len(),
                    expected,
                    "expected all {expected} slots resolved"
                );
                for m in &r.drifted {
                    eprintln!(
                        "DRIFT {}: {} compiled {} → runtime {:?}",
                        m.name, m.struct_name, m.expected, m.actual
                    );
                }
                eprintln!(
                    "OK: {} slots resolved on the running kernel ({} differ from the build)",
                    r.values.len(),
                    r.drifted.len()
                );
            }
            ResolveOutcome::SkippedNoBtf { reason } => {
                panic!("no /sys/kernel/btf/vmlinux on this host — cannot run VM check: {reason}");
            }
            ResolveOutcome::Refuse(RefuseReason::Drift(ms)) => {
                for m in &ms {
                    eprintln!("MISSING {}: {} — {}", m.name, m.struct_name, m.detail);
                }
                panic!(
                    "{} field(s) unresolvable on the running kernel (see stderr)",
                    ms.len()
                );
            }
            ResolveOutcome::Refuse(RefuseReason::ParseError(e)) => panic!("BTF parse error: {e}"),
        }
    }

    #[test]
    fn resolve_with_reports_drift_but_resolves() {
        let btf = parsed();
        // Use real SLOT_TABLE names so slots resolve; outer.a is byte 0,
        // inner.x is byte 8 in the fixture.
        let specs = &[
            OffsetSpec {
                name: SLOT_TABLE[0].0,
                struct_name: "outer",
                field_path: &["a"],
                expected: 0,
                alt_paths: &[],
                optional: false,
            },
            OffsetSpec {
                name: SLOT_TABLE[1].0,
                struct_name: "inner",
                field_path: &["x"],
                expected: 4, // compiled-in value "wrong" for this kernel
                alt_paths: &[],
                optional: false,
            },
        ];
        match resolve_with(&btf, specs, &[], &|_| None) {
            ResolveOutcome::Resolved(r) => {
                assert_eq!(r.values, vec![(SLOT_TABLE[0].1, 0), (SLOT_TABLE[1].1, 8)]);
                assert_eq!(r.drifted.len(), 1);
                assert_eq!(r.drifted[0].actual, Some(8));
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn resolve_with_refuses_on_missing_field() {
        let btf = parsed();
        let specs = &[OffsetSpec {
            name: SLOT_TABLE[0].0,
            struct_name: "outer",
            field_path: &["zzz"],
            expected: 0,
            alt_paths: &[],
            optional: false,
        }];
        assert!(matches!(
            resolve_with(&btf, specs, &[], &|_| None),
            ResolveOutcome::Refuse(RefuseReason::Drift(m)) if m.len() == 1 && m[0].actual.is_none()
        ));
    }

    #[test]
    fn every_revalidate_spec_has_a_slot() {
        for spec in REVALIDATE {
            assert!(
                SLOT_TABLE.iter().any(|(n, _)| *n == spec.name),
                "{}",
                spec.name
            );
        }
    }

    #[test]
    fn optional_missing_field_is_absent_not_refused() {
        let btf = parsed();
        let specs = &[OffsetSpec {
            name: SLOT_TABLE[0].0,
            struct_name: "outer",
            field_path: &["zzz"],
            expected: 0,
            alt_paths: &[],
            optional: true,
        }];
        match resolve_with(&btf, specs, &[], &|_| None) {
            ResolveOutcome::Resolved(r) => {
                assert_eq!(r.values, vec![(SLOT_TABLE[0].1, BTF_OFFSETS_ABSENT)]);
                assert_eq!(r.absent.len(), 1);
            }
            other => panic!("expected Resolved with an absent slot, got {other:?}"),
        }
    }

    /// A module struct whose members use the module's own names, the
    /// base's names (deduplicated strings) and the base's types.
    fn base_and_module() -> (Vec<u8>, Vec<u8>) {
        let mut b = BtfBuilder::new();
        let u32_id = b.int("u32");
        let x_off = b.str("x");
        let inner = b.composite(Some("inner"), false, false, &[(x_off, u32_id, 64)]);
        let (base_types, base_strs) = (b.next_id, b.strings.len() as u32);
        let base = b.build();
        let mut m = BtfBuilder::split_on(base_types, base_strs);
        let root_off = m.str("root");
        let vfs_off = m.str("vfs_inode");
        let anon_off = m.str("anon_dev");
        let root_ty = m.composite(Some("btrfs_root"), false, false, &[(anon_off, u32_id, 64)]);
        let _bi = m.composite(
            Some("btrfs_inode"),
            false,
            false,
            &[
                (root_off, root_ty, 0),
                (x_off, u32_id, 32),
                (vfs_off, inner, 128),
            ],
        );
        (base, m.build())
    }

    #[test]
    fn split_btf_resolves_module_structs_over_the_base() {
        let (base, module) = base_and_module();
        let base = Btf::parse(&base).expect("base parses");
        let split = SplitBtf::parse(&base, &module).expect("module parses");
        assert_eq!(split.resolve_path("btrfs_inode", &["root"]).unwrap(), 0);
        // member name from the base's strings
        assert_eq!(split.resolve_path("btrfs_inode", &["x"]).unwrap(), 4);
        // member type from the base: vfs_inode is the base's `inner`
        assert_eq!(
            split
                .resolve_path("btrfs_inode", &["vfs_inode", "x"])
                .unwrap(),
            24
        );
        assert_eq!(split.resolve_path("btrfs_root", &["anon_dev"]).unwrap(), 8);
        // the base's own structs stay reachable through the module view
        assert_eq!(split.resolve_path("inner", &["x"]).unwrap(), 8);
        assert!(base.resolve_path("btrfs_inode", &["root"]).is_err());
    }

    fn btrfs_specs() -> Vec<OffsetSpec> {
        REVALIDATE
            .iter()
            .filter(|s| s.struct_name.starts_with("btrfs_"))
            .copied()
            .collect()
    }

    #[test]
    fn module_structs_resolve_from_the_module_btf() {
        let (base, module) = base_and_module();
        let base = Btf::parse(&base).expect("base parses");
        let specs = btrfs_specs();
        assert_eq!(specs.len(), 3);
        let loaded = |m: &str| (m == "btrfs").then(|| module.clone());
        match resolve_with(&base, &specs, &[], &loaded) {
            ResolveOutcome::Resolved(r) => {
                let slot = |n: &str| SLOT_TABLE.iter().find(|(s, _)| *s == n).unwrap().1;
                assert!(r.values.contains(&(slot("BTRFS_INODE_ROOT_OFFSET"), 0)));
                assert!(r
                    .values
                    .contains(&(slot("BTRFS_INODE_VFS_INODE_OFFSET"), 16)));
                assert!(r.values.contains(&(slot("BTRFS_ROOT_ANON_DEV_OFFSET"), 8)));
                assert!(r.absent.is_empty() && r.modules_not_loaded.is_empty());
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn module_not_loaded_is_unset_not_degraded() {
        let (base, _) = base_and_module();
        let base = Btf::parse(&base).expect("base parses");
        match resolve_with(&base, &btrfs_specs(), &[], &|_| None) {
            ResolveOutcome::Resolved(r) => {
                assert_eq!(r.values.len(), 3);
                assert!(r.values.iter().all(|(_, v)| *v == BTF_OFFSETS_ABSENT));
                assert!(r.absent.is_empty(), "a missing module is not a degradation");
                assert_eq!(r.modules_not_loaded, vec!["btrfs"]);
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn unparseable_module_btf_is_a_degradation() {
        let (base, _) = base_and_module();
        let base = Btf::parse(&base).expect("base parses");
        let garbage = |_: &str| Some(vec![0u8; 8]);
        match resolve_with(&base, &btrfs_specs(), &[], &garbage) {
            ResolveOutcome::Resolved(r) => {
                assert_eq!(r.absent.len(), 3);
                assert!(r.absent[0].detail.contains("module BTF: btrfs"));
                assert!(r.modules_not_loaded.is_empty());
            }
            other => panic!("expected Resolved with absent entries, got {other:?}"),
        }
    }
}
