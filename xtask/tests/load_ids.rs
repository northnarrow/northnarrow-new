//! Lot 303: the module-load hooks on 7.0 — the parts no host test runs.
//!
//! 7.0 added `READING_MODULE_COMPRESSED` to `enum kernel_read_file_id`: a
//! `finit_module(2)` with `MODULE_INIT_COMPRESSED_FILE` (kmod's load of a
//! `.ko.zst`, every module of Ubuntu 26.04) reads its file with that id,
//! which the hook skipped — on the nightly's 7.0 guest no module load was
//! judged or recorded (the R018 e2e red from 05/11, the module_load
//! self-test missed every round). The eBPF program runs only in a kernel
//! (the lab: an untrusted compressed copy refused on our 7.0 guest); here
//! the code is read: the hook takes both ids from the shared copy, and the
//! attach leaves both hooks out, signed, where the kernel's BTF gives
//! another value for one of them.

mod support;

use std::fs;

use support::{repo_root, strip_comments};

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
        .unwrap_or_else(|| panic!("fn {name} not found"));
    let open = start + code[start..].find('{').expect("a body");
    let len = support::matching_brace(&code[open..]);
    &code[open..open + len]
}

/// Named (lot 303): `kernel_read_file`'s hook judges a compressed module's
/// read like a plain one, the kexec image is refused first, and every id
/// is `common::module_judge::read_id`'s — no literal of its own.
#[test]
fn the_read_hook_judges_a_compressed_module_s_read() {
    let m = code("agent-ebpf/src/module_load.rs");
    in_order(
        body(&m, "try_read_file"),
        &[
            "let id: c_int = ctx.arg(1);",
            "if id == KEXEC_IMAGE {\n        return deny_kexec(id);\n    }",
            "if !reads_module_file(id as u32) {\n        return 0;\n    }",
            "judge_file(file as *const u8)",
            "emit_module_load(MODULE_LOAD_FINIT, file, &j);",
        ],
    )
    .unwrap();
    assert!(m.contains("const KEXEC_IMAGE: c_int = read_id::KEXEC_IMAGE as c_int;"));
    assert!(m.contains("const LOADING_MODULE: c_int = read_id::LOADING_MODULE as c_int;"));
    assert!(!m.contains("READING_MODULE"), "an id of its own");
    in_order(
        body(&m, "try_load_data"),
        &[
            "let id: c_int = ctx.arg(0);",
            "if id == KEXEC_IMAGE {",
            "if id != LOADING_MODULE {",
        ],
    )
    .unwrap();
}

/// Named (lot 303): the boot's BTF check of the ids keeps both load hooks
/// out — each one counted an observe failure with the reason, a prior
/// boot's pins of its hook purged — before any attach; matching ids attach
/// them as before.
#[test]
fn other_load_ids_keep_the_module_hooks_out() {
    let f = code("crates/nn-linux/src/anti_tamper/filesystem.rs");
    in_order(
        body(&f, "attach"),
        &[
            "let drift = super::btf_revalidate::resolved()\n        .map(|r| r.read_id_drift.clone())",
            "for (program, hook) in MODULE_LOAD_PROGRAMS {",
            "if let Some(why) = read_ids_refusal(&drift) {",
            "antitamper_bpf::lsm_pin_paths(root, hook);",
            "antitamper_bpf::purge_stale_pin(&link);",
            "antitamper_bpf::purge_stale_pin(&prog);",
            "health.observe_failures.push((program, why));\n            continue;",
            "super::reattach_fresh(ebpf, program, hook, btf, pin_root)",
        ],
    )
    .unwrap();
    let b = code("crates/nn-linux/src/anti_tamper/btf_revalidate.rs");
    assert!(b.contains("let read_id_drift = read_id_drift(btf);"));
    assert!(b.contains(
        "common::module_judge::read_id_drift(|e, n| btf.resolve_enum(e, n).ok().map(i64::from))"
    ));
}
