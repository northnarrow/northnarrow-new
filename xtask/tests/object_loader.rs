//! Lot 400 (aya 0.16): every load of the agent's eBPF object starts from
//! one loader, `nn_linux::sensors::ebpf_object::object_loader`.
//!
//! aya 0.14's `EbpfLoader::btf(None)` — the object loaded with no target
//! BTF — is gone in 0.16: a fresh `EbpfLoader::new()` reads
//! `/sys/kernel/btf/vmlinux` by path whenever an object carries a CO-RE
//! relocation or a typed kernel symbol. `object_loader` keeps 0.14's load
//! with a target-BTF source that refuses (no relocation, no `/sys` walk: the
//! agent reads the kernel's views beneath its anchored roots only), and
//! nn-linux's `the_object_needs_no_target_btf` holds the object to it. A
//! second loader built elsewhere would drop that, quietly: no product file
//! but the loader's own builds an `EbpfLoader`, sets a target BTF, or loads
//! through `Ebpf::load*`. The scan is lexical (comments blanked, test items
//! and test-only files left out), and each rule is shown failing on a
//! planted violation.

mod support;

use support::{product_code, repo_root};

/// The loader's module: the one place an `EbpfLoader` is built.
const LOADER: &str = "crates/nn-linux/src/sensors/ebpf_object.rs";

/// What builds or loads outside the loader: (needle, why).
const FORBIDDEN: &[(&str, &str)] = &[
    (
        "EbpfLoader::new(",
        "a loader of its own reads a target BTF by path (aya 0.16): use object_loader()",
    ),
    (
        "EbpfLoader::default(",
        "a loader of its own reads a target BTF by path (aya 0.16): use object_loader()",
    ),
    (
        "Ebpf::load(",
        "Ebpf::load is EbpfLoader::new().load: use object_loader()",
    ),
    (
        "Ebpf::load_file(",
        "Ebpf::load_file is EbpfLoader::new().load_file: use object_loader()",
    ),
    (".btf_source(", "the target BTF is object_loader's to set"),
    (".btf(&", "the target BTF is object_loader's to set"),
];

/// The violations of `code` (one file's production code) outside the loader.
fn violations(rel: &str, code: &str) -> Vec<String> {
    if rel == LOADER {
        return Vec::new();
    }
    FORBIDDEN
        .iter()
        .filter(|(needle, _)| code.contains(needle))
        .map(|(needle, why)| format!("{rel}: `{needle}` — {why}"))
        .collect()
}

/// Named (lot 400): no product file but the loader's builds an aya loader,
/// loads through `Ebpf::load*` or sets a target BTF.
#[test]
fn every_load_of_the_object_starts_from_object_loader() {
    let root = repo_root();
    let code = product_code(&root);
    assert!(
        code.contains_key(LOADER),
        "{LOADER} is not among the product files"
    );
    let bad: Vec<String> = code
        .iter()
        .flat_map(|(rel, text)| violations(rel, text))
        .collect();
    assert!(bad.is_empty(), "{bad:#?}");
    // and the sites that load the object use it
    for rel in [
        "crates/nn-linux/src/sensors/multiplexer.rs",
        "crates/nn-linux/src/sensors/exec.rs",
        "crates/nn-linux/src/verifier_check.rs",
        "crates/nn-linux/src/sensor_feasibility.rs",
    ] {
        assert!(
            code[rel].contains("ebpf_object::object_loader()"),
            "{rel} loads the eBPF object without object_loader()"
        );
    }
}

/// Named (lot 400): the loader itself gives aya a target-BTF source that
/// refuses — not `EbpfLoader::new()` alone, whose default reads
/// `/sys/kernel/btf/vmlinux` by path.
#[test]
fn object_loader_refuses_a_target_btf() {
    let code = product_code(&repo_root());
    let loader = &code[LOADER];
    let start = loader
        .find("fn object_loader")
        .expect("fn object_loader in the loader's module");
    let open = start + loader[start..].find('{').expect("a body");
    let body = &loader[open..open + support::matching_brace(&loader[open..])];
    for needle in [
        "aya::EbpfLoader::new()",
        "loader.btf_source(|_| {",
        "Err(aya::EbpfError::BtfSourceError(",
    ] {
        assert!(
            body.contains(needle),
            "object_loader lost `{needle}`: {body}"
        );
    }
    assert!(
        !body.contains("from_sys_fs") && !body.contains(".btf(&"),
        "object_loader reads or sets a target BTF: {body}"
    );
}

/// Each rule fails on a planted violation, and the loader's own file is
/// exempt.
#[test]
fn the_rules_catch_a_planted_loader() {
    for (needle, _) in FORBIDDEN {
        let planted = format!("fn f() {{ let _ = {needle}x); }}");
        assert_eq!(
            violations("agent/src/main.rs", &planted).len(),
            1,
            "{needle} not caught"
        );
        assert!(violations(LOADER, &planted).is_empty());
    }
    assert!(violations("agent/src/main.rs", "fn f() { object_loader().load(b) }").is_empty());
}
