# EBPF_001 — BTF/CO-RE offset resolution (Option 3, held)

**Status:** Step 1 (boot revalidator) **SHIPPED as BUG-036**; portability
is the open item — see the **CO-RE-lite plan of record (2026-06-08)** at the
end of this doc. Original hold decision 2026-05-29, green-light message:
"Hold Option 3 (BTF/CO-RE offset resolution) as follow-up hardening. Keep
PF_KTHREAD as the signal (reads correctly on real 6.8)".
**Severity:** HARDENING — robustness against kernel-upgrade offset drift.
Not a correctness bug on the current fleet (Ubuntu 24.04 / 6.8.x).
**Predecessor:** the cluster-15 staleness guard
(`docs/design/EBPF_OBJECT_STALENESS_GUARD_DESIGN.md`) shipped first; it
closes the *stale object* class. This follow-up closes the *wrong offset*
class.

## Problem

`agent-ebpf/src/btf_offsets.rs` hard-codes kernel struct field byte
offsets (`TASK_STRUCT_FLAGS_OFFSET = 44`, `TASK_STRUCT_REAL_PARENT_OFFSET`,
the `sock` / `tcp_sock` / `iov_iter` sets, etc.) captured from one
kernel's `/sys/kernel/btf/vmlinux`. A kernel upgrade can shift any of
them. Today the only protection is:

- the per-offset BTF-dump provenance comments (a manual re-validation aid,
  not an enforced check), and
- R011's specific **fail-secure** posture: an unreadable / wrong-offset
  `parent->flags` read leaves `parent_is_kthread = 0`, which over-fires
  rather than under-fires.

Fail-secure saves R011 specifically. It does **not** save offsets whose
wrong value silently mis-reads (e.g. an argv pointer landing on the wrong
`mm_struct` field, or a net offset mis-attributing a flow).

## Proposed fix (Option 3)

Resolve the offsets at load time instead of hard-coding them:

1. **Boot-time BTF revalidator (cheaper, do first):** the userland loader
   reads `/sys/kernel/btf/vmlinux`, looks up each `(struct, field)` the
   eBPF program depends on, and asserts the running kernel's offset equals
   the compiled-in constant. Mismatch → fail LOUD at attach (refuse to run
   on a kernel whose layout the constants don't match), the same
   fail-closed posture as the staleness guard. This is the
   `btf_offsets.rs` module-header TODO ("the planned boot-time BTF
   revalidator … will fail LOUD on drift").
2. **Full CO-RE (larger):** emit real CO-RE field relocations so the
   verifier/loader fixes offsets per-kernel automatically. Blocked on
   aya-ebpf emitting CO-RE relocations from Rust struct definitions
   (aya-ebpf 0.1 does not — hence the hard-coded offsets in the first
   place). Revisit when the aya-ebpf version in `agent-ebpf/Cargo.toml`
   gains CO-RE support.

## Why it can wait

- The production fleet is a known kernel (Ubuntu 24.04 / 6.8.x); the
  offsets are dump-validated against it (see the dated provenance comments
  in `btf_offsets.rs`).
- The PF_KTHREAD path — the one that triggered cluster 15 — is
  fail-secure on a bad read, so the worst case is the (now correctly
  diagnosable) over-fire, not a missed rootkit install.
- The staleness guard removed the actual incident cause. This is the next
  layer down, not the same bug.

## Acceptance

- A boot-time check that fails loud when any depended-on offset differs
  from the running kernel's BTF, with a test that injects a deliberately
  wrong offset and asserts the loud refusal.

---

## Update 2026-06-08 — boot revalidator shipped; CO-RE-lite is the post-beta plan of record

Step 1 above shipped as **BUG-036** (`agent::anti_tamper::btf_revalidate`,
VM-verified 6.8.0-117): on layout drift the agent fail-closes (exit 78)
instead of silently reading garbage. That closed the *wrong-offset* class but
not the *portability* one — running on a kernel whose layout differs **without
refusing**. This section banks the plan of record for portability, from a
read-only recon of the offset model. It supersedes Step 2 (Full CO-RE) as the
near-term direction; Step 2 stays the long-term end state, still blocked on the
toolchain.

### Finding: offsets are compile-baked, and the deriver we need already exists — and is discarded

- Every offset is a Rust `const usize` in `common::btf_offsets`, re-exported by
  `agent-ebpf::btf_offsets`, used directly in `ptr.add(CONST)` feeding
  `bpf_probe_read_kernel`. `bpf-linker` folds each into an immediate — there is
  **no runtime indirection** (the loader calls `loader.btf(None)`; no CO-RE).
  ~47 deref sites across 10 eBPF files.
- BUG-036's revalidator **already derives the correct offset for every spec
  from the running kernel's BTF** — then **throws it away**: `revalidate_with`
  compares `actual == expected` and returns only `Verified { count }`; on drift
  the derived value rides a `Mismatch` to the log line, then exit 78.
- **Consequence:** CO-RE-lite is a *wiring* job, not a new capability. The hard,
  security-critical part — resolving `(struct, field_path)` against running BTF,
  anonymous-union descent, bitfield rejection — is built and proven. The work
  is to route those derived values into the eBPF half instead of discarding them.

### The CO-RE-lite move — two carrier strategies

Convert each `ptr.add(CONST)` site to read a per-kernel offset the agent writes
at load time, sourced from the BTF the revalidator already parses.

- **Carrier A — `.rodata` globals via aya `set_global` (preferred).** Declare
  each offset as an aya-ebpf global; userland calls
  `loader.set_global(name, &derived, true)` *before* `load()`. The verifier then
  sees frozen `.rodata` constants — **same verifier characteristics as today's
  `const`s**, so minimal re-verification churn. *Unknown to spike first:*
  aya-ebpf 0.1's global-variable support is thin — confirm a `#[no_mangle]
  static` is rewritable by aya 0.13 `set_global` and readable via `read_volatile`
  in-program. If it holds, this is the lowest-friction path.
- **Carrier B — pinned `Array<u64>` offsets map (matches the existing idiom).**
  Add an `Array` map, populate it after load (the `WATCHED_PATHS` pattern), read
  `OFFSETS.get(IDX)` per site. A map value is an *unbounded scalar*, so each site
  needs a verifier bounds guard (`if off > MAX { return }`) plus a lookup per
  deref. More robust against toolchain limits; more verifier iteration.

### Effort — ~1 sprint, eBPF-side dominated

- **Agent side — small (~0.5 d).** Add a `derive_offsets()` beside
  `revalidate_with` (reuse the resolver; collect instead of compare). Route the
  values into `set_global` / the Array at the two load sites
  (`sensors::multiplexer`, `sensors::exec`).
- **eBPF side — the bulk (~2–4 d incl. VM verifier iteration).** Convert the ~47
  deref sites + imports from `CONST` to a global/map read; (B only) add bounds
  guards; re-pass the verifier for every program on a real LSM kernel.
- **Carrier spike (~0.5–1 d):** prove A on the toolchain, else fall back to B.

### SECURITY FLIP — the posture inverts; guard it deliberately

Today the deriver is a **fail-closed gate**: an unexpected/unresolved offset →
refuse to start (safe). CO-RE-lite turns the *same code* into a **trusted value
source** — its output is written into the programs and attached. The failure
mode inverts: a plausible-but-wrong derived offset would now **attach hooks on
the wrong kernel memory** instead of refusing. Non-negotiable guards for the
CO-RE-lite build:

- **Derive-or-refuse.** Any field that fails to resolve → refuse (exit 78),
  never attach with a zero/guessed offset. Keep BUG-036's fail-closed posture
  for the *unresolved* case; only the *resolved-and-different* case changes from
  "refuse" to "use".
- **Sanity-bound every derived offset** (e.g. within the struct's BTF size)
  before trusting it — a value outside plausible range → refuse.
- **Multi-kernel fire-tests on the VM** (≥2 kernel versions with BPF-LSM), never
  WSL2 — the map/`.rodata`-read verifier behaviour differs from compile-time
  consts and only validates on a real LSM kernel.

### Scope notes

- CO-RE-lite fixes *offset portability*, **not BPF-LSM availability**
  (`CONFIG_BPF_LSM` + `lsm=` boot param remain prerequisites; tracepoint/kprobe
  sensors run regardless, the LSM hooks do not).
- The tracepoint-format offsets (`FILENAME_*`, `FLAGS_OFFSET` in
  `exec_check`/`file_open`/`main`) are a *different ABI* — the
  `events/.../format` contract, not BTF struct offsets — so they are out of
  scope for BTF derivation; they would need a separate tracepoint-format check
  if ever hardened.
- The `msghdr` struct offsets `MSGHDR_NAME_OFFSET` / `MSGHDR_NAMELEN_OFFSET`
  were the one BTF-offset gap the recon found *outside* the gate; they were
  **folded into `common::btf_offsets` + `REVALIDATE` (2026-06-08)** so they
  fail-close like the rest. The revalidation contract now covers **40** offsets
  (was 38).

### Recommendation

Build CO-RE-lite (carrier A, fall back to B) as the post-beta portability step;
it reuses the BUG-036 investment almost wholesale. **Do not** ship a per-kernel
offset *profile*: a runtime-selected profile is impossible against baked
immediates (that indirection *is* this refactor), and a compile-time profile
won't even match a given 6.6 build (struct layout is `CONFIG`-dependent, not
version-dependent) and is a per-kernel allowlist — the opposite of portability.
Full CO-RE (Step 2) stays blocked on aya-ebpf emitting field relocations from
Rust struct defs; revisit on an aya-ebpf upgrade. **This is the plan of record.**
