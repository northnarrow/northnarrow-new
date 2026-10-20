# NOTICES

NorthNarrow is licensed under the Apache License, Version 2.0 (`LICENSE`).
It is built from the third-party crates below, each under its own terms.
This file and `LICENSE` ship with every release: at the root of the
tarball's tree, and in `/usr/share/doc/northnarrow/` from a package.

## Which files are under which terms

| Material | Where it is | Terms |
|---|---|---|
| NorthNarrow's own code, configuration and documentation | everything not named below | Apache-2.0 — `LICENSE` |
| Rust crates from crates.io | compiled into `northnarrow-agent`, `northnarrow-watchdog` and `nn-admin` | each crate's own licence (below) |

Wave 4 (lab PR 214): the third-party material of the on-host LLM advisor
left the tree with the advisor, and so did its sections of this file — the
MITRE ATT&CK® content and the distilled SigmaHQ rules of its RAG knowledge
base (`cargo xtask rag-kb`, and the ATT&CK notes built into the agent),
with their licence texts; the vendored, modified `candle-core` 0.10.2; and
the note on its model (Foundation-Sec-8B-Reasoning, which no release ever
distributed). A release made before Wave 4 carries its own `NOTICES.md`
for what it held.

## Rust crates (crates.io)

The three binaries statically link the crates `Cargo.lock` pins, each under
its own licence. The per-crate list (name, version, licence) is in the
release's CycloneDX SBOMs (`*.sbom.cdx.json`); on a checkout,
`cargo tree -e normal -p northnarrow-agent --format "{p} {l}"` (and
`-p northnarrow-watchdog`) prints it. On 2026-10-20, after the removal of
the on-host LLM advisor (Wave 4, lab PR 214), the licence expressions of
the crates the binaries link used only MIT, Apache-2.0 (with or without the
LLVM exception), BSD-2-Clause, BSD-3-Clause, Zlib, Unicode-3.0 and
Unlicense.

## Licence declarations

- `Cargo.toml` (the workspace `license`, which every member inherits),
  `agent-ebpf/Cargo.toml` and the `.rpm` (`License:`) say `Apache-2.0`, the
  licence of `LICENSE`. The expression covers NorthNarrow's own code; the
  third-party material above keeps the terms this file gives for it.
- The eBPF object declares `Dual MIT/GPL` in its `license` section
  (`agent-ebpf/src/main.rs`): the kernel loads LSM programs only when that
  section names a GPL-compatible licence, so it cannot say `Apache-2.0`.
  That declaration and the `Apache-2.0` of `agent-ebpf/Cargo.toml` do not
  say the same thing. Whether the eBPF programs are also offered under MIT
  or GPL-2.0 is a decision for the maintainer, still open.
