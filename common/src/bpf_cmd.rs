//! The uapi `enum bpf_cmd` numbers (`include/uapi/linux/bpf.h`), the one
//! copy the eBPF programs (`agent-ebpf`, `default-features = false`) and
//! userland compile.
//!
//! Lab PR 215 (capability C23): the `bpf` LSM hook carried its own copy
//! with `BPF_LINK_GET_FD_BY_ID = 31`. The uapi value is 30; 31 is
//! `BPF_LINK_GET_NEXT_ID`. Counting the enumerators by hand gives 31,
//! because `BPF_PROG_RUN = BPF_PROG_TEST_RUN` is an alias that takes no
//! number of its own. A handle on one of the agent's links taken by id
//! was therefore neither refused nor recorded. The enumeration step of
//! `bpftool link list` (`LINK_GET_NEXT_ID` starting from one of the
//! agent's link ids) was refused instead, and recorded as an anti-tamper
//! denial (NN-L-AT-001, COMBAT). `bpf_cmd_name` repeated the same 31.
//! Every number is now defined here only. The tests compare each one with
//! the uapi header of the build host and with `enum bpf_cmd` in the
//! running kernel's BTF (`crates/nn-linux/src/anti_tamper/btf_revalidate.rs`), and
//! fail when anything else in the tree defines one of these numbers again.
//!
//! `u32`: the hook reads `cmd` as the kernel's `int` and compares it as
//! unsigned (no command is negative); the syscall wrappers cast to
//! `c_long`.

/// `BPF_MAP_CREATE`.
pub const BPF_MAP_CREATE: u32 = 0;
/// Lot 349 (the review of #558, F1): `BPF_MAP_UPDATE_ELEM` — of a prog
/// array, it puts a program in a tail call's slot.
pub const BPF_MAP_UPDATE_ELEM: u32 = 2;
/// `BPF_MAP_GET_NEXT_KEY` (the privileged e2e reads `OWN_BPF_IDS` with it).
pub const BPF_MAP_GET_NEXT_KEY: u32 = 4;
/// `BPF_PROG_LOAD`.
pub const BPF_PROG_LOAD: u32 = 5;
/// `BPF_OBJ_PIN`.
pub const BPF_OBJ_PIN: u32 = 6;
/// `BPF_OBJ_GET`: opens a pinned object by path.
pub const BPF_OBJ_GET: u32 = 7;
/// `BPF_PROG_ATTACH`.
pub const BPF_PROG_ATTACH: u32 = 8;
/// `BPF_PROG_DETACH`.
pub const BPF_PROG_DETACH: u32 = 9;
/// Lot 349 (the review of #558, F1): `BPF_PROG_TEST_RUN` (`BPF_PROG_RUN`
/// is its alias, a later name: the older kernels' BTF has this one) — runs
/// a program, a `syscall` program's only way to run.
pub const BPF_PROG_TEST_RUN: u32 = 10;
/// `BPF_PROG_GET_NEXT_ID`: enumeration, no handle.
pub const BPF_PROG_GET_NEXT_ID: u32 = 11;
/// `BPF_MAP_GET_NEXT_ID`: enumeration, no handle.
pub const BPF_MAP_GET_NEXT_ID: u32 = 12;
/// `BPF_PROG_GET_FD_BY_ID`: a program handle by id.
pub const BPF_PROG_GET_FD_BY_ID: u32 = 13;
/// `BPF_MAP_GET_FD_BY_ID`: a map handle by id.
pub const BPF_MAP_GET_FD_BY_ID: u32 = 14;
/// `BPF_OBJ_GET_INFO_BY_FD`.
pub const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;
/// `BPF_RAW_TRACEPOINT_OPEN`: attaches a program — a raw tracepoint, and
/// through it (libbpf before `LINK_CREATE` took them, and any caller since)
/// `tp_btf`, `fentry`/`fexit`/`fmod_ret` and LSM programs. External bug hunt
/// BUG05: the `bpf` hook did not look at it, so an attach this way left no
/// record (the load's stayed).
pub const BPF_RAW_TRACEPOINT_OPEN: u32 = 17;
/// `BPF_BTF_LOAD`.
pub const BPF_BTF_LOAD: u32 = 18;
/// `BPF_MAP_FREEZE`: the agent freezes `BTF_OFFSETS` with it.
pub const BPF_MAP_FREEZE: u32 = 22;
/// `BPF_LINK_CREATE`.
pub const BPF_LINK_CREATE: u32 = 28;
/// `BPF_LINK_UPDATE`: replaces a link's program (by link fd).
pub const BPF_LINK_UPDATE: u32 = 29;
/// `BPF_LINK_GET_FD_BY_ID`: a link handle by id, the one handle that could
/// detach or update a hook.
pub const BPF_LINK_GET_FD_BY_ID: u32 = 30;
/// `BPF_LINK_GET_NEXT_ID`: enumeration, no handle (the first step of each
/// entry of `bpftool link list`).
pub const BPF_LINK_GET_NEXT_ID: u32 = 31;
/// `BPF_ITER_CREATE`: a readable descriptor of an iterator link (lot 290:
/// the cross-view's enumeration).
pub const BPF_ITER_CREATE: u32 = 33;
/// `BPF_LINK_DETACH`: detaches a link (by link fd).
pub const BPF_LINK_DETACH: u32 = 34;

/// Lot 280b: `enum bpf_attach_type`'s `BPF_CGROUP_SYSCTL` — not a command:
/// the attach type at +8 of `BPF_PROG_ATTACH` and `BPF_LINK_CREATE`'s
/// `union bpf_attr`.
pub const ATTACH_CGROUP_SYSCTL: u32 = 18;

/// Lot 280b: where a command that attaches a program to a cgroup carries
/// the cgroup's descriptor in `union bpf_attr`: `BPF_PROG_ATTACH`'s
/// `target_fd` at 0, `BPF_LINK_CREATE`'s at 4 (after `prog_fd`); `None` for
/// any other command. Both carry the attach type at 8.
#[inline(always)]
pub const fn attach_target_offset(cmd: u32) -> Option<usize> {
    match cmd {
        BPF_PROG_ATTACH => Some(0),
        BPF_LINK_CREATE => Some(4),
        _ => None,
    }
}

/// Lot 280b: an attach whose target the `bpf` hook judges — a
/// `cgroup/sysctl` program's (refused on the root cgroup outside the
/// agent's family and a window: after the agent's judge, it would run
/// after it and could rewrite the value judged).
#[inline(always)]
pub const fn judges_attach_target(cmd: u32, attach_type: u32) -> bool {
    attach_target_offset(cmd).is_some() && attach_type == ATTACH_CGROUP_SYSCTL
}

/// Lot 349 (the review of #558, F1): where a command that RUNS or ATTACHES
/// a program carries that program's descriptor in `union bpf_attr` —
/// `BPF_PROG_RUN`'s `test.prog_fd` (0), `BPF_PROG_ATTACH`'s
/// `attach_bpf_fd` (4, after `target_fd`), `BPF_RAW_TRACEPOINT_OPEN`'s
/// `raw_tracepoint.prog_fd` (8, after the name's pointer),
/// `BPF_LINK_CREATE`'s `link_create.prog_fd` (0) and `BPF_LINK_UPDATE`'s
/// `new_prog_fd` (4, after `link_fd`); `None` for any other command. A
/// prog array's `BPF_MAP_UPDATE_ELEM` carries it behind the value's
/// pointer ([`MAP_UPDATE_VALUE_OFFSET`]). The `bpf` hook refuses each of
/// them on a program held at a window's load.
#[inline(always)]
pub const fn prog_fd_offset(cmd: u32) -> Option<usize> {
    match cmd {
        BPF_PROG_TEST_RUN | BPF_LINK_CREATE => Some(0),
        BPF_PROG_ATTACH | BPF_LINK_UPDATE => Some(4),
        BPF_RAW_TRACEPOINT_OPEN => Some(8),
        _ => None,
    }
}

/// Lot 349: `BPF_MAP_UPDATE_ELEM`'s `value` pointer in `union bpf_attr`
/// (after `map_fd` and the key's pointer); its `map_fd` is at 0.
pub const MAP_UPDATE_VALUE_OFFSET: usize = 16;

/// Lot 349: `enum bpf_map_type`'s `BPF_MAP_TYPE_PROG_ARRAY` — a tail
/// call's table, whose values are program descriptors.
pub const MAP_TYPE_PROG_ARRAY: u32 = 3;

/// Lot 349 (the re-check of #558, N1): a prog array's update value (the
/// program's descriptor) as the `bpf` hook could read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotValue {
    /// The descriptor, to judge as a run or an attach is.
    Fd(u32),
    /// Neither read gave it: the update is refused, signed (fail closed).
    Unreadable,
}

/// Lot 349 (the re-check of #558, N1): the value of a prog array's
/// `BPF_MAP_UPDATE_ELEM` from its two reads — `user` through the user path
/// (a `bpf(2)` call's pointer), `kernel` through the kernel path, tried
/// only when the user one failed (`bpf_sys_bpf` from a `syscall` program
/// passes a kernel pointer, which the user path refuses). The user path is
/// nofault: a page not resident fails it while the kernel's own copy, after
/// the hook, may fault it in — so a value neither read gives is
/// [`SlotValue::Unreadable`], refused, never let through (the slot could
/// take a program held at a window's load, run by a clean program's tail
/// call with no hook at all).
#[inline(always)]
pub const fn slot_value(user: Option<u32>, kernel: Option<u32>) -> SlotValue {
    match (user, kernel) {
        (Some(fd), _) | (None, Some(fd)) => SlotValue::Fd(fd),
        (None, None) => SlotValue::Unreadable,
    }
}

/// Lot 349 (the review of #558, F1): `PERF_EVENT_IOC_SET_BPF`
/// (`_IOW('$', 8, __u32)`, include/uapi/linux/perf_event.h) — attaches the
/// program whose descriptor is the `ioctl`'s argument to a perf event (a
/// kprobe, a tracepoint): no `bpf(2)` command at all, so the `file_ioctl`
/// hook judges it.
pub const PERF_EVENT_IOC_SET_BPF: u32 = 0x4004_2408;

/// Every number above with its uapi name, for the checks against the
/// header and the kernel's BTF. A command added above goes here too
/// (`every_constant_is_listed` checks it).
pub const UAPI: [(&str, u32); 23] = [
    ("BPF_MAP_CREATE", BPF_MAP_CREATE),
    ("BPF_MAP_UPDATE_ELEM", BPF_MAP_UPDATE_ELEM),
    ("BPF_MAP_GET_NEXT_KEY", BPF_MAP_GET_NEXT_KEY),
    ("BPF_PROG_LOAD", BPF_PROG_LOAD),
    ("BPF_OBJ_PIN", BPF_OBJ_PIN),
    ("BPF_OBJ_GET", BPF_OBJ_GET),
    ("BPF_PROG_ATTACH", BPF_PROG_ATTACH),
    ("BPF_PROG_DETACH", BPF_PROG_DETACH),
    ("BPF_PROG_TEST_RUN", BPF_PROG_TEST_RUN),
    ("BPF_PROG_GET_NEXT_ID", BPF_PROG_GET_NEXT_ID),
    ("BPF_MAP_GET_NEXT_ID", BPF_MAP_GET_NEXT_ID),
    ("BPF_PROG_GET_FD_BY_ID", BPF_PROG_GET_FD_BY_ID),
    ("BPF_MAP_GET_FD_BY_ID", BPF_MAP_GET_FD_BY_ID),
    ("BPF_OBJ_GET_INFO_BY_FD", BPF_OBJ_GET_INFO_BY_FD),
    ("BPF_RAW_TRACEPOINT_OPEN", BPF_RAW_TRACEPOINT_OPEN),
    ("BPF_BTF_LOAD", BPF_BTF_LOAD),
    ("BPF_MAP_FREEZE", BPF_MAP_FREEZE),
    ("BPF_LINK_CREATE", BPF_LINK_CREATE),
    ("BPF_LINK_UPDATE", BPF_LINK_UPDATE),
    ("BPF_LINK_GET_FD_BY_ID", BPF_LINK_GET_FD_BY_ID),
    ("BPF_LINK_GET_NEXT_ID", BPF_LINK_GET_NEXT_ID),
    ("BPF_ITER_CREATE", BPF_ITER_CREATE),
    ("BPF_LINK_DETACH", BPF_LINK_DETACH),
];

/// The commands the `bpf` LSM hook looks at (`BpfSyscallRaw` records, the
/// link-handle deny, the detach and update deny). The busy ones (map
/// lookups and updates, `OBJ_GET_INFO_BY_FD`, `PROG_RUN`) and the
/// `*_GET_NEXT_ID` enumerations, which give no handle, are not among them.
/// The hook calls this function, so the host tests check the same set.
#[inline(always)]
pub const fn observed(cmd: u32) -> bool {
    matches!(
        cmd,
        BPF_MAP_CREATE
            | BPF_PROG_LOAD
            | BPF_OBJ_PIN
            | BPF_OBJ_GET
            | BPF_PROG_ATTACH
            | BPF_PROG_DETACH
            | BPF_PROG_GET_FD_BY_ID
            | BPF_MAP_GET_FD_BY_ID
            | BPF_RAW_TRACEPOINT_OPEN
            | BPF_BTF_LOAD
            | BPF_LINK_CREATE
            | BPF_LINK_UPDATE
            | BPF_LINK_GET_FD_BY_ID
            | BPF_LINK_DETACH
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    /// Where the build host's uapi header lives (linux-libc-dev,
    /// kernel-headers): every host that links the workspace with the
    /// system C toolchain has it.
    const UAPI_HEADER: &str = "/usr/include/linux/bpf.h";

    /// The enumerators of `enum <name>` in a C header, with their values
    /// as the C compiler assigns them: one more than the previous
    /// enumerator, or an explicit number, or the value of an earlier
    /// enumerator named on the right of `=` (`BPF_PROG_RUN =
    /// BPF_PROG_TEST_RUN`), after which counting resumes from that value.
    /// `None` when the header has no such enum or an entry it cannot read.
    fn c_enum(header: &str, name: &str) -> Option<BTreeMap<String, i64>> {
        let start = header.find(&format!("enum {name} {{"))?;
        let body = &header[start..];
        let body = &body[body.find('{')? + 1..body.find("};")?];
        let mut text = String::new();
        let mut rest = body;
        while let Some(i) = rest.find("/*") {
            text.push_str(&rest[..i]);
            rest = &rest[i + 2 + rest[i + 2..].find("*/")? + 2..];
        }
        text.push_str(rest);
        let text: String = text
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        let mut out = BTreeMap::new();
        let mut next: i64 = 0;
        for entry in text.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            let (ident, value) = match entry.split_once('=') {
                None => (entry, next),
                Some((ident, rhs)) => {
                    let rhs = rhs.trim();
                    let value = match rhs.parse::<i64>() {
                        Ok(v) => v,
                        Err(_) => *out.get(rhs)?,
                    };
                    (ident.trim(), value)
                }
            };
            if ident.is_empty()
                || !ident
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return None;
            }
            out.insert(ident.to_string(), value);
            next = value + 1;
        }
        Some(out)
    }

    /// Our values that disagree with `enumerators`, or that it does not
    /// have: `(name, ours, theirs)`.
    fn mismatches(
        ours: &[(&'static str, u32)],
        enumerators: &BTreeMap<String, i64>,
    ) -> Vec<(&'static str, u32, Option<i64>)> {
        ours.iter()
            .filter(|(name, value)| enumerators.get(*name) != Some(&i64::from(*value)))
            .map(|(name, value)| (*name, *value, enumerators.get(*name).copied()))
            .collect()
    }

    /// Lab PR 215: every number the tree uses is the build host's uapi
    /// one. With `BPF_LINK_GET_FD_BY_ID` back at 31 this fails, naming it.
    #[test]
    fn bpf_cmd_values_match_the_uapi_header() {
        let header = std::fs::read_to_string(UAPI_HEADER).unwrap_or_else(|e| {
            panic!(
                "{UAPI_HEADER}: {e} — the bpf_cmd numbers are checked against the uapi \
                 header of the build host (Debian/Ubuntu: linux-libc-dev; Fedora/RHEL: \
                 kernel-headers)"
            )
        });
        let enumerators =
            c_enum(&header, "bpf_cmd").expect("enum bpf_cmd readable in the uapi header");
        let wrong = mismatches(&UAPI, &enumerators);
        assert!(
            wrong.is_empty(),
            "bpf_cmd numbers that differ from {UAPI_HEADER} (name, ours, the header's): {wrong:?}"
        );
    }

    /// Lot 280b: the attach type the `bpf` hook judges is the header's,
    /// and only the two attaching commands carry it there.
    #[test]
    fn the_judged_attach_is_the_headers_cgroup_sysctl() {
        let header = std::fs::read_to_string(UAPI_HEADER).expect("the uapi header");
        let types = c_enum(&header, "bpf_attach_type").expect("enum bpf_attach_type");
        assert_eq!(
            types.get("BPF_CGROUP_SYSCTL"),
            Some(&i64::from(ATTACH_CGROUP_SYSCTL))
        );
        assert!(judges_attach_target(BPF_PROG_ATTACH, ATTACH_CGROUP_SYSCTL));
        assert!(judges_attach_target(BPF_LINK_CREATE, ATTACH_CGROUP_SYSCTL));
        assert_eq!(attach_target_offset(BPF_PROG_ATTACH), Some(0));
        assert_eq!(attach_target_offset(BPF_LINK_CREATE), Some(4));
        for (_, cmd) in UAPI {
            if cmd != BPF_PROG_ATTACH && cmd != BPF_LINK_CREATE {
                assert!(!judges_attach_target(cmd, ATTACH_CGROUP_SYSCTL), "{cmd}");
                assert_eq!(attach_target_offset(cmd), None, "{cmd}");
            }
        }
        // another attach type on the same commands: not judged
        for t in [0u32, 17, 19, 27] {
            assert!(!judges_attach_target(BPF_LINK_CREATE, t), "{t}");
            assert!(!judges_attach_target(BPF_PROG_ATTACH, t), "{t}");
        }
    }

    /// The parser counts the way the C compiler does: an alias takes no
    /// number of its own. A count of the lines (the way the wrong 31 came
    /// about) is one too many from `BPF_PROG_RUN` on.
    #[test]
    fn the_header_parser_follows_c_enum_rules() {
        let header = "enum other { A, B };\n\
            enum bpf_cmd {\n\tBPF_MAP_CREATE,\n\tBPF_PROG_TEST_RUN = 10, /* run */\n\
            \tBPF_PROG_RUN = BPF_PROG_TEST_RUN,\n\tBPF_PROG_GET_NEXT_ID, // 11\n\
            \tBPF_LINK_UPDATE = 29,\n\tBPF_LINK_GET_FD_BY_ID,\n\tBPF_LINK_GET_NEXT_ID,\n\
            \t__MAX_BPF_CMD,\n};\n";
        let e = c_enum(header, "bpf_cmd").expect("parsed");
        assert_eq!(e["BPF_MAP_CREATE"], 0);
        assert_eq!(e["BPF_PROG_RUN"], 10);
        assert_eq!(e["BPF_PROG_GET_NEXT_ID"], 11);
        assert_eq!(e["BPF_LINK_GET_FD_BY_ID"], 30);
        assert_eq!(e["BPF_LINK_GET_NEXT_ID"], 31);
        assert!(!e.contains_key("A"));
        assert!(c_enum(header, "bpf_missing").is_none());
        assert!(c_enum("enum bpf_cmd { X = Y, };", "bpf_cmd").is_none());
        let drifted = [("BPF_LINK_GET_FD_BY_ID", 31), ("BPF_PROG_RUN", 10)];
        assert_eq!(
            mismatches(&drifted, &e),
            vec![("BPF_LINK_GET_FD_BY_ID", 31, Some(30))]
        );
        assert_eq!(
            mismatches(&[("BPF_TOKEN_CREATE", 36)], &e),
            vec![("BPF_TOKEN_CREATE", 36, None)]
        );
    }

    /// Every `pub const` of this module is in [`UAPI`] (what the checks
    /// read), once.
    #[test]
    fn every_constant_is_listed() {
        let src = include_str!("bpf_cmd.rs");
        let consts: Vec<&str> = src
            .lines()
            .filter_map(|l| l.strip_prefix("pub const BPF_"))
            .filter_map(|l| l.split(':').next())
            .collect();
        assert_eq!(consts.len(), UAPI.len(), "{consts:?}");
        for c in consts {
            let name = format!("BPF_{c}");
            assert_eq!(
                UAPI.iter().filter(|(n, _)| *n == name).count(),
                1,
                "{name} listed once in UAPI"
            );
        }
    }

    /// Lab PR 215: the hook looks at a link handle taken by id and not at
    /// the enumeration — the commands the wrong number swapped.
    #[test]
    fn the_hook_sees_handles_and_not_enumerations() {
        for cmd in [
            BPF_LINK_GET_FD_BY_ID,
            BPF_MAP_GET_FD_BY_ID,
            BPF_PROG_GET_FD_BY_ID,
            BPF_OBJ_GET,
            BPF_LINK_DETACH,
            BPF_LINK_UPDATE,
        ] {
            assert!(observed(cmd), "{cmd}");
        }
        for cmd in [
            BPF_LINK_GET_NEXT_ID,
            BPF_MAP_GET_NEXT_ID,
            BPF_PROG_GET_NEXT_ID,
            BPF_MAP_FREEZE,
            BPF_MAP_GET_NEXT_KEY,
            BPF_OBJ_GET_INFO_BY_FD,
        ] {
            assert!(!observed(cmd), "{cmd}");
        }
    }

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("common lives one level below the repository root")
            .to_path_buf()
    }

    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// A line that gives one of the uapi names a number of its own: `const
    /// BPF_LINK_GET_FD_BY_ID: c_int = 31;`, `const BPF_OBJ_GET_CMD:
    /// libc::c_long = 7;`.
    fn defines_a_number(line: &str) -> Option<&'static str> {
        let decl = line.trim_start();
        let decl = decl.strip_prefix("pub ").unwrap_or(decl);
        let decl = decl.strip_prefix("const ")?;
        let (ident, rest) = decl.split_once(':')?;
        let ident = ident.trim();
        let ident = ident.strip_suffix("_CMD").unwrap_or(ident);
        let (name, _) = UAPI.iter().find(|(n, _)| *n == ident)?;
        let value = rest.split_once('=')?.1.trim().trim_end_matches(';').trim();
        value
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_digit())
            .then_some(*name)
    }

    /// Lab PR 215: no other source defines one of these numbers. The two
    /// copies that drifted (the hook's, `bpf_cmd_name`'s) and the four
    /// that happened to be right (the BPF rules', the agent's `OBJ_GET` and
    /// `MAP_FREEZE` wrappers, a decision test's) all read this module now.
    /// Wave 4 restructure, R09a (lab PR 253): `crates/` too — the BPF rules
    /// and the decision test moved to nn-core (R08b), the wrappers to
    /// nn-linux with the self-defence (R09a), out of the directories below.
    #[test]
    fn no_other_copy_of_a_bpf_cmd_number() {
        assert_eq!(
            defines_a_number("const BPF_LINK_GET_FD_BY_ID: c_int = 31;"),
            Some("BPF_LINK_GET_FD_BY_ID")
        );
        assert_eq!(
            defines_a_number("    const BPF_OBJ_GET_CMD: libc::c_long = 7;"),
            Some("BPF_OBJ_GET")
        );
        assert_eq!(
            defines_a_number("const BPF_OBJ_GET: libc::c_long = bpf_cmd::BPF_OBJ_GET as _;"),
            None
        );
        assert_eq!(defines_a_number("const BPF_NOEXIST: u64 = 1;"), None);
        let root = repo_root();
        let mut files = Vec::new();
        for dir in [
            "agent/src",
            "agent/tests",
            "agent/examples",
            "agent-ebpf/src",
            "antitamper-bpf/src",
            "cli/src",
            "common/src",
            "crates",
            "watchdog/src",
            "watchdog/tests",
            "xtask/src",
            "fuzz/fuzz_targets",
        ] {
            rust_files(&root.join(dir), &mut files);
        }
        assert!(
            files
                .iter()
                .any(|f| f.ends_with("agent-ebpf/src/bpf_defense.rs")),
            "the eBPF sources are in the scan"
        );
        assert!(
            files
                .iter()
                .any(|f| f.ends_with("crates/nn-linux/src/anti_tamper/bpf_defense.rs")),
            "the crates are in the scan"
        );
        let own = root.join("common/src/bpf_cmd.rs");
        let mut found = Vec::new();
        for file in files.iter().filter(|f| **f != own) {
            let text = std::fs::read_to_string(file).unwrap_or_default();
            for (n, line) in text.lines().enumerate() {
                if let Some(name) = defines_a_number(line) {
                    found.push(format!("{}:{}: {name}", file.display(), n + 1));
                }
            }
        }
        assert!(
            found.is_empty(),
            "bpf_cmd numbers defined outside common/src/bpf_cmd.rs: {found:?}"
        );
    }

    /// Lot 349 (the re-check of #558, N1): a prog array's value the user
    /// path could not read (a page not resident, `bpf_sys_bpf`'s kernel
    /// pointer) was let through; the kernel path's read is taken then, and
    /// a value neither gives is refused — never a pass.
    #[test]
    fn a_prog_array_value_neither_path_reads_is_refused() {
        assert_eq!(slot_value(Some(7), None), SlotValue::Fd(7));
        assert_eq!(slot_value(None, Some(9)), SlotValue::Fd(9), "bpf_sys_bpf");
        assert_eq!(slot_value(Some(7), Some(9)), SlotValue::Fd(7), "user first");
        assert_eq!(slot_value(None, None), SlotValue::Unreadable);
    }

    /// Lot 349 (the review of #558, F1): every command that runs or
    /// attaches a program names where its descriptor sits — the uapi
    /// `union bpf_attr` layout, literal on purpose — and none that only
    /// reads or detaches does; `PERF_EVENT_IOC_SET_BPF` is `_IOW('$', 8,
    /// __u32)`.
    #[test]
    fn every_run_and_attach_names_its_program_descriptor() {
        // include/uapi/linux/bpf.h: test.prog_fd, attach_bpf_fd after
        // target_fd, raw_tracepoint.prog_fd after the u64 name,
        // link_create.prog_fd, link_update.new_prog_fd after link_fd
        assert_eq!(prog_fd_offset(10), Some(0), "BPF_PROG_RUN");
        assert_eq!(prog_fd_offset(8), Some(4), "BPF_PROG_ATTACH");
        assert_eq!(prog_fd_offset(17), Some(8), "BPF_RAW_TRACEPOINT_OPEN");
        assert_eq!(prog_fd_offset(28), Some(0), "BPF_LINK_CREATE");
        assert_eq!(prog_fd_offset(29), Some(4), "BPF_LINK_UPDATE");
        for cmd in [0, 1, 2, 3, 4, 5, 6, 7, 9, 13, 15, 30, 33, 34] {
            assert_eq!(prog_fd_offset(cmd), None, "{cmd}");
        }
        assert_eq!(MAP_UPDATE_VALUE_OFFSET, 16, "map_fd u32 + pad, key u64");
        assert_eq!(MAP_TYPE_PROG_ARRAY, 3);
        const fn iow(ty: u8, nr: u8, size: u32) -> u32 {
            (1 << 30) | (size << 16) | ((ty as u32) << 8) | nr as u32
        }
        assert_eq!(PERF_EVENT_IOC_SET_BPF, iow(b'$', 8, 4));
    }

    /// External bug hunt BUG05: `BPF_RAW_TRACEPOINT_OPEN` (uapi 17)
    /// attaches a program (raw_tp; tp_btf / fentry / fexit / LSM through
    /// legacy libbpf), like `PROG_ATTACH` and `LINK_CREATE`: the `bpf`
    /// hook promises a record for an attach. The number is the literal on
    /// purpose (the test reads the same on a tree without the constant);
    /// `bpf_cmd_values_match_the_uapi_header` ties the name to it.
    #[test]
    fn raw_tracepoint_open_is_observed() {
        const RAW_TRACEPOINT_OPEN: u32 = 17; // include/uapi/linux/bpf.h
        assert!(observed(BPF_PROG_ATTACH));
        assert!(observed(BPF_LINK_CREATE));
        assert!(
            observed(RAW_TRACEPOINT_OPEN),
            "BPF_RAW_TRACEPOINT_OPEN (17) attaches a program and the bpf hook does not look at it"
        );
    }
}
