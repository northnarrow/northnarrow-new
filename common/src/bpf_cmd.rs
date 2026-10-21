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
//! running kernel's BTF (`agent/src/anti_tamper/btf_revalidate.rs`), and
//! fail when anything else in the tree defines one of these numbers again.
//!
//! `u32`: the hook reads `cmd` as the kernel's `int` and compares it as
//! unsigned (no command is negative); the syscall wrappers cast to
//! `c_long`.

/// `BPF_MAP_CREATE`.
pub const BPF_MAP_CREATE: u32 = 0;
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
/// `BPF_LINK_DETACH`: detaches a link (by link fd).
pub const BPF_LINK_DETACH: u32 = 34;

/// Every number above with its uapi name, for the checks against the
/// header and the kernel's BTF. A command added above goes here too
/// (`every_constant_is_listed` checks it).
pub const UAPI: [(&str, u32); 19] = [
    ("BPF_MAP_CREATE", BPF_MAP_CREATE),
    ("BPF_MAP_GET_NEXT_KEY", BPF_MAP_GET_NEXT_KEY),
    ("BPF_PROG_LOAD", BPF_PROG_LOAD),
    ("BPF_OBJ_PIN", BPF_OBJ_PIN),
    ("BPF_OBJ_GET", BPF_OBJ_GET),
    ("BPF_PROG_ATTACH", BPF_PROG_ATTACH),
    ("BPF_PROG_DETACH", BPF_PROG_DETACH),
    ("BPF_PROG_GET_NEXT_ID", BPF_PROG_GET_NEXT_ID),
    ("BPF_MAP_GET_NEXT_ID", BPF_MAP_GET_NEXT_ID),
    ("BPF_PROG_GET_FD_BY_ID", BPF_PROG_GET_FD_BY_ID),
    ("BPF_MAP_GET_FD_BY_ID", BPF_MAP_GET_FD_BY_ID),
    ("BPF_OBJ_GET_INFO_BY_FD", BPF_OBJ_GET_INFO_BY_FD),
    ("BPF_BTF_LOAD", BPF_BTF_LOAD),
    ("BPF_MAP_FREEZE", BPF_MAP_FREEZE),
    ("BPF_LINK_CREATE", BPF_LINK_CREATE),
    ("BPF_LINK_UPDATE", BPF_LINK_UPDATE),
    ("BPF_LINK_GET_FD_BY_ID", BPF_LINK_GET_FD_BY_ID),
    ("BPF_LINK_GET_NEXT_ID", BPF_LINK_GET_NEXT_ID),
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
}
