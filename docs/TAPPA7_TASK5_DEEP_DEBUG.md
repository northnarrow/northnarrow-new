# Tappa 7 Task 5 — Deep Debug Log

**Date:** 2026-05-12
**Branch:** main, HEAD `10eb29b` (drop prev-retval reads)
**Scope:** filesystem-protection LSM hooks (inode_unlink, inode_rmdir,
inode_rename, inode_setattr, file_ioctl) are loaded and "attached" but
not denying any attack.

This document is updated incrementally as the investigation proceeds.
The user will `cat` it instead of scrolling tmux.

---

## 0. Starting State Summary (post-reboot, clean env)

**Attack matrix — all PASSED for attacker (FAIL for protection):**

| Command   | rc | Expected | Outcome |
|-----------|----|----------|---------|
| `chattr -i`  | 0 | -EPERM | attacker wins |
| `mv`         | 0 | -EPERM | attacker wins |
| `touch`      | 0 | -EPERM | attacker wins |
| `chmod`      | 0 | -EPERM | attacker wins |
| `rm <file>`  | 0 | -EPERM | attacker wins |

**Kernel state:**
- 7/7 LSM programs visible in `bpftool prog show`.
- Agent log reports all 7 attached cleanly.
- `PROTECTED_INODES` map populated: `dev=2049 ino=1282701`.
- Reboot performed, no stale BPF programs from previous attempts.

**`trace_pipe` output during attack run — the smoking gun:**

```
mv-1195 ... nn-diag-ioctl-body fired
mv-1195 ... nn-diag-rename-body fired
```

That is the **entire** output. Two lines, both from `mv` (PID 1195).
Zero output from `chattr`, `touch`, `chmod`, `rm`. No `nn_printk_u64`
output at all — not even `"nn-diag: ENTER inode_rename"` (line 301 of
`inode_protect.rs`), which sits *right after* the rename body marker
that we *did* see fire.

---

## 1. Source Inspection — Current Wrappers

All seven `#[lsm]` programs live in three files:

| File | Hook | Body marker present? |
|---|---|---|
| `agent-ebpf/src/inode_protect.rs:236` | `inode_unlink` | **NO** |
| `agent-ebpf/src/inode_protect.rs:264` | `inode_rmdir` | **NO** |
| `agent-ebpf/src/inode_protect.rs:285` | `inode_rename` | yes (line 293) |
| `agent-ebpf/src/inode_protect.rs:327` | `inode_setattr` | **NO** |
| `agent-ebpf/src/inode_protect.rs:348` | `file_ioctl` | yes (line 355) |
| `agent-ebpf/src/task_kill.rs:56` | `task_kill` | n/a (off-path) |
| `agent-ebpf/src/ptrace_check.rs:61` | `ptrace_access_check` | n/a (off-path) |

**Body marker = unconditional zero-arg `bpf_printk!(b"...")`** at the
top of the wrapper, *before* any `ctx.arg()` or helper call. Currently
only `inode_rename` and `file_ioctl` carry one.

**Flow inside each wrapper:**

```
fn <hook>(ctx) -> i32 {
    [optional body marker]
    unsafe { try_<hook>(&ctx) }
}

unsafe fn try_<hook>(ctx) -> i32 {
    // 1. Pull args via ctx.arg(N) — these are kernel-trusted PTR_TO_BTF_ID.
    // 2. For dentry args: inode_from_dentry() does ONE bpf_probe_read_kernel.
    // 3. deny_if_protected(op, inode_ptr):
    //      inode_key()       — TWO bpf_probe_read_kernel calls (s_dev, i_ino)
    //      is_protected(&k)  — HashMap::get
    //      override_active() — Array::get
    //      emit_denial()     — RingBuf::reserve + submit
    //      → returns true = caller emits -EPERM
}
```

**Diagnostic helpers in use today:**
- `bpf_printk!(b"…")` (zero-arg form). aya 0.13 macro path that is
  *known to work* — this is what produced the only two trace lines we
  see.
- `nn_printk_u64(fmt, value)` — local helper calling
  `bpf_trace_vprintk` directly. Used inside `deny_if_protected` and
  scattered through `try_inode_rename` / `try_file_ioctl`. **Zero
  observed output from this path** in the current run.

---

## 2. Hypotheses

### A) BPF programs attached to the wrong BTF id.

`bpftool prog show` reporting "lsm" type with the right name does not
prove that the kernel routes `security_inode_unlink` calls to *our*
program — only that the program is loaded. The `attach_btf_id` field
must match `vmlinux.btf::security_inode_unlink`.

Evidence for A:
- Five of five FS hooks behave identically (no deny, no trace) for
  every attack except `mv` and the random ioctls `mv` itself issues.
- That `mv` does trigger the rename and ioctl body markers means the
  *kernel-side dispatch* is working at least for those two hook names.
- `inode_unlink` etc. produce no body marker because we never added
  one — so for those three hooks we currently *cannot distinguish*
  "kernel never called it" from "kernel called it but our logic
  didn't trip". This must be fixed before we can blame A.

### B) `nn_printk_u64` is broken on this kernel/aya combo.

This is the single most suspicious thing in the current trace. We
have:

- `bpf_printk!(b"nn-diag-rename-body fired")` at line 293 — **fires**.
- `nn_printk_u64(b"nn-diag: ENTER inode_rename", 0)` at line 301,
  five Rust statements later, on the same control path — **silent**.

There is no branch between those two lines. If the first prints and
the second doesn't, either:
- `bpf_trace_vprintk` (helper #177) is being called but the verifier /
  kernel is dropping the output (e.g. fmt buffer not in `.rodata`, or
  helper signature mismatch in aya 0.13's binding), or
- the call is failing verification silently in a way that doesn't
  prevent load (unlikely — verifier failures abort load), or
- the call is generating the output but to a different ring than
  `trace_pipe`.

The `bpf_trace_vprintk` path is non-standard. The aya 0.13 helper for
this helper is a bare `extern "C"` thunk in `helpers/mod.rs` and may
not handle the fmt-buffer relocation that a CO-RE `.rodata` reference
needs on this kernel.

**Likelihood: very high.** Replace all `nn_printk_u64` in
`deny_if_protected` with zero-arg `bpf_printk!` markers. If we then
see them in `trace_pipe`, B is confirmed.

### C) Body markers are not actually at the start of execution.

The `#[lsm]` proc macro could in principle insert verifier-visible
prologue (arg shuffling, ctx normalisation) before our marker. If a
silent failure happens there, the marker fires (we see it) but the
real arg reads then return null/garbage and every `deny_if_protected`
takes the `inode_key=None` branch.

Evidence against C: we see *some* nn_printk_u64 calls compile and
load; we just don't see their output. If C were the case, body marker
+ the `inode_key=None` `nn_printk_u64` would both produce output
(under a B-fixed printk).

### D) Hook is firing but `inode_key` always returns `None`.

If `INODE_I_SB_OFFSET` / `SUPER_BLOCK_S_DEV_OFFSET` / `INODE_I_INO_OFFSET`
are wrong for Ubuntu 6.8, `bpf_probe_read_kernel` returns `Err(_)` and
we silently take the `None` branch — every hook becomes a pure
pass-through. Cannot be ruled out without working printk.

---

## 3. Test plan (this iteration)

The single experiment that disambiguates A vs. B vs. D:

1. Add unconditional zero-arg body markers to the three hooks that
   lack them (`inode_unlink`, `inode_rmdir`, `inode_setattr`).
   → answers "did the kernel call us?" for `rm`, `rmdir`, `chmod`,
   `touch`.

2. Replace every `nn_printk_u64` inside `deny_if_protected` with a
   zero-arg `bpf_printk!` marker.
   → answers "did control reach `deny_if_protected`?" and "which
   branch did it take?".

3. Leave existing `nn_printk_u64` calls in `try_inode_rename` /
   `try_file_ioctl` *in place* as the control: if zero-arg markers
   appear but those don't, B is confirmed and we should rip the
   bpf_trace_vprintk helper out wholesale.

Markers added:

| Marker | Meaning |
|---|---|
| `nn-diag-unlink-body fired`  | inode_unlink dispatched |
| `nn-diag-rmdir-body fired`   | inode_rmdir dispatched |
| `nn-diag-setattr-body fired` | inode_setattr dispatched |
| `nn-diag-REACHED-deny-if`    | entered deny_if_protected |
| `nn-diag-REACHED-key-none`   | inode_key() returned None |
| `nn-diag-REACHED-key-ok`     | inode_key() succeeded |
| `nn-diag-REACHED-MISS`       | key not in PROTECTED_INODES |
| `nn-diag-REACHED-MATCH`      | key matched, no override → will deny |
| `nn-diag-REACHED-OVERRIDE`   | key matched, override active → pass-through |

---

## 4. Bugs identified

*(populated as findings land)*

1. **(suspected — pending confirmation) aya 0.13 `bpf_trace_vprintk`
   binding silently drops output on Ubuntu 6.8 BPF-LSM trampoline.**
   Attribution: aya 0.13 helpers binding (not kernel, not our code).
   Workaround: avoid the helper, use the macro path with zero-arg
   form. Confirmation step: this diagnostic build.

2. **(our code) three of five FS hook wrappers lack a body marker,
   making "kernel never called us" indistinguishable from "kernel
   called us, logic short-circuited".** Attribution: our code.
   Workaround: add the markers (this iteration).

---

## 5. Open questions

- Once we know which hooks the kernel actually invokes, do the
  `attach_btf_id` values match `vmlinux.btf` for the hooks that did
  *not* invoke us? (Needs `bpftool prog show id N -j` per program.)
- Are the `btf_offsets.rs` offsets verified against this kernel's
  vmlinux? (`agent` loader is supposed to verify at boot, but let's
  re-check after we know printk works.)
- Why did `chattr -i` produce *no* ioctl-body marker when `mv`
  triggered the same hook via routine ioctls? Either `chattr` is on a
  different code path (unlikely — it's a textbook
  `ioctl(FS_IOC_SETFLAGS)`) or its ioctl arrives after our hook is
  unregistered/replaced/etc. To investigate after printk works.

---

## 6. Next steps

1. Apply edits described in §3 → build → commit locally.
2. User runs attack matrix + dumps `trace_pipe` → pastes results.
3. Update §0 with new attack table, §4 with confirmed bugs, §5/§6
   with the next question.
