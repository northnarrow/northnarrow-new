# EBPF_001 — BTF/CO-RE offset resolution (Option 3, held)

**Status:** DEFERRED — held as follow-up hardening (decision 2026-05-29,
green-light message: "Hold Option 3 (BTF/CO-RE offset resolution) as
follow-up hardening. Keep PF_KTHREAD as the signal (reads correctly on
real 6.8)").
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
