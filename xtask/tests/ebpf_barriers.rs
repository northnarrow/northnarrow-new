//! Lot 1.2 (aya-ebpf 0.3, rustc 1.99's LLVM 22): the bounds the verifier
//! needs are tested on the register the program then uses. LLVM moved
//! three of them where the verifier could not see them, and the exec
//! programs were refused on 5.15 and 6.12: the filename's read size
//! bounded on the whole `__data_loc` word, a path level's slot masks
//! dropped after a range test made on a copy, the exec policy's verdict
//! folded into `-(deny & 1) & -EACCES`. Each is now taken through
//! `agent-ebpf/src/opaque.rs` (a volatile read of a local: a value the
//! compiler knows nothing about). Here the code is read: each of the three
//! sites keeps its barrier before its test, and a barrier written by hand
//! anywhere else is one of the two that predate the helper.

mod support;

// The helpers' own source, built for the host: `lsm_ret`'s verdicts are run,
// not only read (the review of #618).
#[path = "../../agent-ebpf/src/opaque.rs"]
mod opaque;

use std::fs;

use support::{matching_brace, repo_root, strip_comments};

fn code(rel: &str) -> String {
    strip_comments(
        &fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}")),
    )
}

/// `needles` all in `hay`, in this order.
fn in_order(hay: &str, needles: &[&str]) -> Result<(), String> {
    let mut at = 0;
    for n in needles {
        match hay[at..].find(n) {
            Some(i) => at += i + n.len(),
            None => return Err(format!("{n:?} not found after byte {at}")),
        }
    }
    Ok(())
}

/// The body of `fn name` (to its matching brace).
fn body<'a>(code: &'a str, name: &str) -> &'a str {
    let start = code
        .find(&format!("fn {name}("))
        .or_else(|| code.find(&format!("fn {name}<")))
        .unwrap_or_else(|| panic!("fn {name} not found"));
    let open = start + code[start..].find('{').expect("a body");
    &code[open..open + matching_brace(&code[open..])]
}

/// The two helpers: the barrier itself, and the LSM verdict clamped on the
/// register returned, to the range the verifier allows at an LSM
/// program's exit.
#[test]
fn the_barrier_and_the_lsm_verdict_clamp() {
    let o = code("agent-ebpf/src/opaque.rs");
    assert!(
        body(&o, "opaque").contains("unsafe { core::ptr::read_volatile(&v) }"),
        "the barrier is a volatile read of the local"
    );
    assert!(o.contains("const MAX_ERRNO: i64 = 4095;"));
    assert!(o.contains("const EACCES: i32 = 13;"));
    in_order(
        body(&o, "lsm_ret"),
        &[
            "let v = opaque(i64::from(v));",
            "if v > 0 {\n        -EACCES\n    } else if v < -MAX_ERRNO {\n        -(MAX_ERRNO as i32)\n    } else {\n        v as i32\n    }",
        ],
    )
    .unwrap();
}

/// The review of #618 (P3-2): `lsm_ret` fails closed. A positive verdict,
/// which no deny hook returns, came out as 0, an allow; it is the hook's
/// refusal, `-EACCES`. Every verdict comes out in `[-4095, 0]`, the range
/// the verifier allows at an LSM program's exit, and only 0 allows. The
/// helper's own source, run on the host.
#[test]
fn lsm_ret_allows_only_zero_and_fails_closed() {
    use opaque::lsm_ret;
    // what the hook returns: 0 and its refusal, unchanged
    assert_eq!(lsm_ret(0), 0);
    assert_eq!(lsm_ret(-13), -13);
    // any other -errno, unchanged
    for v in [-1, -2, -4094, -4095] {
        assert_eq!(lsm_ret(v), v, "{v}");
    }
    // positive: no deny hook returns one; the hook's refusal, never 0
    for v in [1, 2, 13, 4095, 4096, i32::MAX] {
        assert_eq!(lsm_ret(v), -13, "{v}");
    }
    // below -MAX_ERRNO: -MAX_ERRNO, a refusal still
    for v in [-4096, -100_000, i32::MIN + 1, i32::MIN] {
        assert_eq!(lsm_ret(v), -4095, "{v}");
    }
    // every value: in the exit range, and 0 only from 0
    for v in (-10_000..=10_000).chain([i32::MIN, i32::MAX]) {
        let r = lsm_ret(v);
        assert!((-4095..=0).contains(&r), "{v} -> {r}");
        assert_eq!(r == 0, v == 0, "{v} -> {r}");
    }
}

/// `lsm_ret`'s refusal is `exec_check_lsm`'s: its one caller is that hook,
/// whose refusals (the exec policy's, the quarantine's) are `-EACCES`. A
/// deny hook with another errno returning through it would turn an
/// impossible positive verdict into the wrong errno: it gets its own.
#[test]
fn lsm_ret_is_the_exec_hooks_and_its_refusal_is_that_hooks_errno() {
    let root = repo_root();
    let mut files = Vec::new();
    support::rs_files(&root.join("agent-ebpf/src"), &mut files);
    let mut calls = Vec::new();
    for f in &files {
        let rel = f
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let n = code(&rel).matches("lsm_ret(").count();
        if rel != "agent-ebpf/src/opaque.rs" && n > 0 {
            calls.push((rel, n));
        }
    }
    assert_eq!(
        calls,
        vec![("agent-ebpf/src/exec_lsm.rs".to_string(), 1)],
        "lsm_ret's one caller is exec_check_lsm"
    );
    for f in ["agent-ebpf/src/execpol.rs", "agent-ebpf/src/execq.rs"] {
        assert!(
            code(f).contains("const EACCES: i32 = 13;"),
            "{f}: the exec hook's refusal is -EACCES"
        );
    }
}

/// The three sites LLVM 22 broke, each with its barrier before the test
/// the verifier needs on the same register.
#[test]
fn the_exec_programs_test_their_bounds_on_the_register_they_use() {
    // the exec tracepoints' filename: the length through the barrier, then
    // the clamp, then the read of at most FILENAME_LEN bytes
    let main = code("agent-ebpf/src/main.rs");
    in_order(
        &main,
        &[
            "let mut f_len = crate::opaque::opaque((data_loc >> 16) & 0xFFFF) as usize;",
            "if f_len > FILENAME_LEN {\n        f_len = FILENAME_LEN;",
            "bpf_probe_read_kernel_buf(src, &mut dst[..f_len])",
        ],
    )
    .unwrap();
    // a path level's slot: the level through the barrier, then both masks
    let q = code("agent-ebpf/src/execq.rs");
    in_order(
        body(&q, "level_name"),
        &[
            "let level = crate::opaque::opaque(level);",
            "let slot = exe_path_slot(level & 63) & 15;",
        ],
    )
    .unwrap();
    // the exec LSM program's verdict, clamped where it returns
    let l = code("agent-ebpf/src/exec_lsm.rs");
    assert!(
        body(&l, "exec_check_lsm")
            .contains("crate::opaque::lsm_ret(unsafe { try_exec_check_lsm(&ctx) })"),
        "exec_check_lsm returns its verdict through lsm_ret"
    );
}

/// A barrier is `opaque`: a `read_volatile(&<local>)` written by hand
/// elsewhere is one of the two that predate the helper (the DNS answer's
/// read size, the ioctl hook's held verdict), each measured on the lab's
/// kernels as it is.
#[test]
fn a_barrier_written_by_hand_is_one_that_predates_the_helper() {
    const PREDATE: [(&str, &str); 2] = [
        ("agent-ebpf/src/dns_answer.rs", "len32"),
        ("agent-ebpf/src/inode_protect.rs", "held"),
    ];
    let root = repo_root();
    let mut files = Vec::new();
    support::rs_files(&root.join("agent-ebpf/src"), &mut files);
    assert!(files.len() > 40, "{} files", files.len());
    let mut found = Vec::new();
    for f in &files {
        let rel = f
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if rel == "agent-ebpf/src/opaque.rs" {
            continue;
        }
        let c = code(&rel);
        let mut from = 0;
        while let Some(at) = c[from..].find("read_volatile(&") {
            let start = from + at + "read_volatile(&".len();
            let local: String = c[start..]
                .chars()
                .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
                .collect();
            if !local.is_empty() && c[start + local.len()..].starts_with(')') {
                found.push((rel.clone(), local));
            }
            from = start;
        }
    }
    found.sort();
    let mut want: Vec<(String, String)> = PREDATE
        .iter()
        .map(|(f, l)| (f.to_string(), l.to_string()))
        .collect();
    want.sort();
    assert_eq!(
        found, want,
        "a compiler barrier goes through crate::opaque::opaque (agent-ebpf/src/opaque.rs)"
    );
}
