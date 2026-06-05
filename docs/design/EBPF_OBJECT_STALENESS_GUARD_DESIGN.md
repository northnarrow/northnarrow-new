# eBPF Object Staleness Guard — Design

**Status:** SHIPPED 2026-05-29 (cluster-15 follow-up, branch `benchmark/cc-t7-13-fix`).
**Severity of the bug it closes:** HIGH — silent detection corruption. A
stale embedded eBPF object made R011 over-fire on benign kworker→modprobe
execs for a full night before the root cause (a stale `.o`, not a logic
bug) was found.
**Scope implemented:** Option 1 (build-dep + staleness/layout-hash guard,
fail-loud-at-build AND refuse-at-startup) + the startup self-check + the
dedicated R011 PF_KTHREAD decision log line. Option 3 (BTF/CO-RE offset
resolution) is explicitly held — see
`docs/follow-ups/EBPF_001_btf_core_offset_resolution.md`.

## The incident

`agent-ebpf/` is a **separate cargo project** (nightly + `rust-src` +
the `bpfel-unknown-none` target), deliberately excluded from the userland
workspace (`Cargo.toml` `exclude = ["agent-ebpf"]`). Only `cargo xtask
build[-ebpf]` compiles it. `agent/build.rs` then `include_bytes!`-embeds
whatever `.o` is sitting in `agent-ebpf/target/…` into the agent binary.

The old `build.rs` copied that `.o` unconditionally and set
`cargo:rerun-if-changed` **only on the artifact path** — never on the
eBPF *source*. So:

- A plain `cargo build --workspace` (CI userland job, IDE `cargo check`,
  or a developer who forgot `xtask`) embedded whatever stale `.o` was on
  disk, with **zero** detection.
- The cluster-15.3 fix added `ProcessSpawnRaw::parent_is_kthread` by
  carving the byte out of reclaimed trailing padding, so the struct
  **size was unchanged (840 bytes)**. The `bytemuck::try_from_bytes`
  size-check at decode time therefore **passed** — the staleness was
  completely invisible on the wire.
- The stale `.o` predated the BPF code that writes `parent_is_kthread`,
  so the field decoded as `0` on every event. R011 reads `0` as
  "not a kernel thread → FIRE" (fail-secure), so it over-fired on the
  legitimate boot-time `kworker → modprobe` hardware-probe execs.

The kernel logic was correct. It was **never compiled in**. A size check
can never catch this class of bug; only a *provenance* check can.

## The guard (two layers + a witness)

### Layer 1 — fail loud at BUILD (the primary fix)

A new shared crate, `ebpf-guard/`, defines the eBPF build's **source
closure** and hashes it (`ebpf_source_hash`): every `.rs` under
`agent-ebpf/src/` and `common/src/` (the shared kernel↔userland wire
types — a change here that is not recompiled into the `.o` is the precise
failure mode), plus the eBPF crate's `Cargo.toml` / `Cargo.lock` /
`rust-toolchain.toml` / `.cargo/config.toml` and `common`'s manifest.

- `cargo xtask build-ebpf` writes that hash to a **stamp** sidecar
  (`…/northnarrow-agent-ebpf.buildhash`) right after a verified compile.
- `agent/build.rs` recomputes the hash over the *current* tree and:
  - **STALE** (stamp present, ≠ current) → `panic!` → the whole build
    fails with the stamped-vs-current diff and the `cargo xtask build`
    remedy.
  - **UNSTAMPED** (`.o` present, no stamp) → `panic!` → provenance
    unknown, refuse.
  - **FRESH** (match) → embed it; record `NN_EBPF_OBJECT_SHA` +
    `NN_EBPF_BUILD_HASH` + `NN_EBPF_EMBEDDED=1` as compile-time env.
  - **ABSENT** (`.o` not built) → empty placeholder + `cargo:warning`,
    `NN_EBPF_EMBEDDED=0`. This keeps userland-only CI / IDE builds green;
    the agent then refuses to *start* (Layer 2).
- `build.rs` now emits `cargo:rerun-if-changed` for the **entire source
  closure**, so an eBPF/wire edit actually re-triggers the check (the
  missing piece that let the staleness slip through originally).

Both the writer (xtask) and the verifier (build.rs) call the same
`ebpf-guard` function, so the hash can never drift between them.

### Layer 2 — refuse at STARTUP (the backstop)

`agent/src/sensors/ebpf_object.rs` is now the single embed site (the two
historical `include_bytes_aligned!` copies in `exec.rs` + `multiplexer.rs`
are gone) and exposes `preflight()`, called early in `main`:

- refuses if `NN_EBPF_EMBEDDED != "1"` or the bytes are empty (a
  placeholder binary built without `xtask` — would run blind);
- recomputes `sha256(EBPF_BYTES)` and refuses if it ≠ the
  `NN_EBPF_OBJECT_SHA` recorded at build (corruption / post-build swap);
- on success logs the auditable boot binding (`object_sha` +
  `build_hash`) so every start records exactly which kernel half is live.

### Layer 3 — install-time witness

`deploy/install.sh::require_fresh_ebpf` refuses to install an agent binary
that is older than the current `.o`/stamp (eBPF rebuilt, agent not) and
requires the stamp to exist. The header + D8 comment block now describe
this enforced reality (the "rebuilt atomically with the agent" claim is
now true by construction, not aspiration).

## Why not just bump a version integer / check size?

- **Size check:** insufficient by construction — the dangerous case keeps
  the size identical (field from reclaimed padding).
- **Hand-maintained version int:** the failure mode is *humans forgetting
  to bump it* — which is exactly how a stale `.o` shipped. The source-hash
  is derived automatically, so it changes precisely when the source does
  (over-conservatively including userland-only `common/` edits, which
  only ever costs an extra eBPF rebuild — the safe direction).

## Observability — R011 decision line

R011 now emits one dedicated, greppable line per kmod-tooling exec on
**both** outcomes (`event = "r011_kthread_decision"`, fields
`parent_is_kthread` / `decision` / `pid` / `comm` / `parent_comm`), at
`debug` level (boot hardware-probe modprobe execs would spam `info`). The
same incident would now read `parent_is_kthread=false decision=fire` at a
glance under `RUST_LOG=…=debug`, instead of being inferred from an
over-fire with no visible cause.

## Files

- `ebpf-guard/` — shared source-closure hash + stamp (new crate).
- `xtask/src/main.rs` — writes the stamp after `build-ebpf`.
- `agent/build.rs` — the staleness guard + env witnesses.
- `agent/src/sensors/ebpf_object.rs` — single embed + `preflight()` (new).
- `agent/src/main.rs` — calls `preflight()` early.
- `agent/src/decision/rules/r011_kernel_module_tooling.rs` — decision line.
- `deploy/install.sh` — `require_fresh_ebpf` + truthful comments.
