# Tappa 7 Task 5 — Deep Debug Log

**Date:** 2026-05-12
**Branch:** main
**Scope:** filesystem-protection LSM hooks (inode_unlink, inode_rmdir,
inode_rename, inode_setattr, file_ioctl) are loaded and "attached" but
not denying any attack.

This document is updated incrementally as the investigation proceeds.
The user will `cat` it instead of scrolling tmux.

---

## 0. Current state (after iteration 1 — commit `3019c24`)

Iteration 1 added unconditional zero-arg `bpf_printk!` body markers
to the three FS hooks that lacked them, and replaced every
`nn_printk_u64` inside `deny_if_protected` with zero-arg
`bpf_printk!` REACHED markers. `nn_printk_u64` was left intact in
`try_inode_rename` / `try_file_ioctl` as a control.

**Attack matrix — all still PASSED for attacker (FAIL for protection):**

| Command   | rc | Expected | Outcome |
|-----------|----|----------|---------|
| `chattr -i`  | 0 | -EPERM | attacker wins |
| `mv`         | 0 | -EPERM | attacker wins |
| `touch`      | 0 | -EPERM | attacker wins |
| `chmod`      | 0 | -EPERM | attacker wins |
| `rm <file>`  | 0 | -EPERM | attacker wins |

**Marker counts from `trace_pipe`:**

| Marker | Hits | Interpretation |
|---|---|---|
| `nn-diag-ioctl-body fired`   | **481** | `security_file_ioctl` hook dispatched (system noise + chattr) |
| `nn-diag-rename-body fired`  | **2**   | `security_inode_rename` hook dispatched (mv only) |
| `nn-diag-unlink-body fired`  | **0**   | `security_inode_unlink` **never dispatched** — rm bypasses our prog |
| `nn-diag-rmdir-body fired`   | **0**   | `security_inode_rmdir` **never dispatched** |
| `nn-diag-setattr-body fired` | **0**   | `security_inode_setattr` **never dispatched** — touch / chmod bypass |
| `nn-diag-REACHED-deny-if`    | **0**   | even on the two hooks the kernel *did* dispatch, control never reached `deny_if_protected` |
| `nn-diag-REACHED-key-none`   | **0**   | (helper not reached) |
| `nn-diag-REACHED-key-ok`     | **0**   | (helper not reached) |
| `nn-diag-REACHED-MISS`       | **0**   | (helper not reached) |
| `nn-diag-REACHED-MATCH`      | **0**   | (helper not reached) |
| `nn-diag: ENTER …` (any `nn_printk_u64`) | **0** | **`bpf_trace_vprintk` path is broken** |

Two independent failures stacked on top of each other:

1. Three of five FS hooks load but the kernel never calls them.
2. The two that *do* get called short-circuit silently between the
   body marker and `deny_if_protected`.

---

## 1. Source inspection — wrappers (post iteration 1)

`agent-ebpf/src/inode_protect.rs`:

| Hook | Body marker | Inner `try_*` instrumentation |
|---|---|---|
| `inode_unlink` (line 242) | yes | none yet (kernel never calls it) |
| `inode_rmdir`  (line 271) | yes | none yet (kernel never calls it) |
| `inode_rename` (line 299) | yes | broken `nn_printk_u64` at line 307 only |
| `inode_setattr` (line 338) | yes | none yet (kernel never calls it) |
| `file_ioctl` (line 365) | yes | broken `nn_printk_u64` at lines 381 / 385 only |

`deny_if_protected` (line 202) now has six zero-arg REACHED markers
covering every branch — none of them fire.

---

## 2. Hypotheses status

### A) BPF programs attached to wrong BTF id — **PARTIALLY CONFIRMED**

`inode_unlink`, `inode_rmdir`, `inode_setattr` body markers fire
**zero** times. `inode_rename` and `file_ioctl` markers fire normally.
Since the body marker is the very first instruction in the wrapper —
unconditional, zero-arg `bpf_printk!`, no `ctx.arg()` before it — the
only explanations are:

1. Kernel BPF-LSM dispatch never invokes our program for those three
   hooks (most likely).
2. The aya 0.13 `#[lsm(hook = "inode_unlink")]` macro is resolving
   `inode_unlink` to the wrong vmlinux BTF id (or none at all) on
   Linux 6.8.

Disambiguation: dump `attach_btf_id` per program from `bpftool prog
show id N -j` and compare against `bpftool btf dump file
/sys/kernel/btf/vmlinux | grep security_inode_unlink`. See test block
in §6.

### B) `nn_printk_u64` / `bpf_trace_vprintk` binding broken — **CONFIRMED**

Zero `nn_printk_u64` calls produced output. Two of them sit
immediately after a working zero-arg `bpf_printk!` body marker on the
same straight-line code path. There is no possible control-flow
explanation; the helper is silently dropping output on this kernel +
aya combo.

Resolution: rip out `nn_printk_u64` and the `bpf_trace_vprintk`
import. Replace remaining call sites with zero-arg `bpf_printk!`.
(Done in iteration 2.)

### C) Body marker fires but inner `try_*` short-circuits silently — **NEW, NOW PRIMARY**

`ioctl-body fires 481 times` but `REACHED-deny-if fires 0 times`.
Almost all 481 hits are non-chattr ioctls returning at the cmd filter,
but `chattr -i` *should* take the FS_IOC_SETFLAGS branch and reach
`deny_if_protected`. Candidate cutoffs:

1. `cmd` value read via `ctx.arg(1)` doesn't match either
   `FS_IOC_SETFLAGS` or `FS_IOC32_SETFLAGS` — modern chattr may issue
   `FS_IOC_FSSETXATTR` (0x4028_5821) instead.
2. `file` pointer at `ctx.arg(0)` is null or garbage.
3. `bpf_probe_read_kernel` of `file->f_inode` returns `Err(_)` because
   `FILE_F_INODE_OFFSET` is wrong on this kernel.
4. `deny_if_protected` is a function call after BPF-backend
   "always-inline" decay and the subprog call itself silently fails
   verification post-load (very speculative).

For `inode_rename`: rename-body fires twice (the test ran `mv` once
and there's a clean-up rename elsewhere maybe). Wrappers call
`deny_if_protected(FS_OP_RENAME, old_dir)` immediately after
`ctx.arg(0)`. Candidate cutoff:
1. `old_dir` is null (unlikely — kernel never passes null to LSM).
2. `deny_if_protected` does not actually get inlined and the subprog
   call is non-functional in BPF context for some reason.

Disambiguation: this iteration adds fine-grained zero-arg markers
between every line of `try_inode_rename` / `try_file_ioctl`. If a
specific marker fires and the next one doesn't, we localise the
cutoff to one line.

### D) `inode_key` always returns `None` (bad BTF offsets) — UNTESTED

We never see `REACHED-key-none` because we never reach
`deny_if_protected` in the first place. Re-evaluate after C is
resolved.

---

## 3. Iteration 2 plan

1. **Rip out `nn_printk_u64`.** Delete the helper, delete the
   `bpf_trace_vprintk` import, replace remaining call sites in
   `try_inode_rename` and `try_file_ioctl` with zero-arg
   `bpf_printk!` markers.
2. **Fine-grained markers inside `try_inode_rename` / `try_file_ioctl`.**
   One marker per decision point so we can localise the cutoff.
3. **Cheap `try-entry` markers in `try_inode_unlink` / `try_inode_rmdir`
   / `try_inode_setattr`.** They cost nothing while those hooks never
   fire and will give us instant feedback when we fix the dispatch.
4. **`cmd`-value forensics in `try_file_ioctl`.** Per-cmd zero-arg
   markers for the four known chattr-family ioctl numbers
   (FS_IOC_SETFLAGS / FS_IOC32_SETFLAGS / FS_IOC_FSSETXATTR /
   FS_IOC_FSGETXATTR). Print only on match, never on "other", to
   keep the 481 noise out of the trace.

Marker inventory after iteration 2:

| Marker | Fires when |
|---|---|
| `nn-diag-{unlink,rmdir,rename,setattr,ioctl}-body fired` | wrapper entry |
| `nn-diag-rename-tryentry` | inside `try_inode_rename` first line |
| `nn-diag-rename-pre-deny-old-dir` | before `deny_if_protected(old_dir)` |
| `nn-diag-rename-pre-deny-new-dir` | before `deny_if_protected(new_dir)` |
| `nn-diag-rename-old-dentry-none` | `inode_from_dentry(old_dentry)` returned None |
| `nn-diag-rename-pre-deny-old-inode` | before `deny_if_protected(old_inode)` |
| `nn-diag-rename-new-dentry-none` | `inode_from_dentry(new_dentry)` returned None |
| `nn-diag-rename-pre-deny-new-inode` | before `deny_if_protected(new_inode)` |
| `nn-diag-ioctl-tryentry` | inside `try_file_ioctl` first line |
| `nn-diag-ioctl-cmd-SETFLAGS` | cmd == FS_IOC_SETFLAGS |
| `nn-diag-ioctl-cmd-SETFLAGS32` | cmd == FS_IOC32_SETFLAGS |
| `nn-diag-ioctl-cmd-FSSETXATTR` | cmd == 0x4028_5821 |
| `nn-diag-ioctl-cmd-FSGETXATTR` | cmd == 0x801c_581f |
| `nn-diag-ioctl-cmd-matched` | passed the cmd-filter early-return |
| `nn-diag-ioctl-file-null` | `file` pointer is null |
| `nn-diag-ioctl-probe-err` | `bpf_probe_read_kernel` on `file->f_inode` failed |
| `nn-diag-ioctl-pre-deny` | about to call `deny_if_protected` |
| `nn-diag-REACHED-deny-if` | entered `deny_if_protected` |
| `nn-diag-REACHED-key-{none,ok}` | `inode_key` result |
| `nn-diag-REACHED-{MISS,MATCH,OVERRIDE}` | decision branch |
| `nn-diag-{unlink,rmdir,setattr}-tryentry` | inner wrapper of the three "never-dispatched" hooks |

---

## 4. Bugs identified

1. **CONFIRMED.** *aya 0.13's `bpf_trace_vprintk` binding silently
   drops output on Linux 6.8 BPF-LSM trampoline.* Attribution: aya
   0.13 (or its interaction with this kernel; not our code). Repro
   smoke-test: a `bpf_trace_vprintk` call placed on a straight-line
   path immediately after a working zero-arg `bpf_printk!` produces
   no `trace_pipe` output. Fix in our codebase: stop using the
   helper, use the macro path exclusively (zero-arg form known to
   work; multi-arg form still suspect per the long comment at line
   42).

2. **PARTIALLY CONFIRMED.** *Three of five FS-protection LSM
   programs load but the kernel never dispatches them
   (inode_unlink, inode_rmdir, inode_setattr).* Attribution: TBD.
   Either aya 0.13's `#[lsm(hook = "…")]` macro resolves the wrong
   vmlinux BTF id for these hook names on Linux 6.8, or our agent
   loader is dropping the attach during program registration.
   Disambiguator: `bpftool prog show id N -j` per program — see §6
   test block.

3. **OPEN.** *On the two hooks the kernel does dispatch
   (inode_rename, file_ioctl), control reaches the wrapper body but
   never reaches `deny_if_protected`.* Iteration 2 instruments every
   line between the two to localise the cutoff. After iteration 2
   results land, this bug becomes either "ctx.arg() returns garbage",
   "cmd value mismatch (chattr uses FSSETXATTR)", "btf-offset bug
   for file->f_inode", or "deny_if_protected subprog call broken".

---

## 5. Open questions

- What `attach_btf_id` is each of the seven LSM progs actually
  using? Specifically the three never-dispatched ones.
- Is the agent loader registering all seven? Or are some failing
  silently at attach? Check the agent startup log for "attach OK"
  per hook.
- What cmd value does the system's `chattr` binary use on Ubuntu
  6.8? Strace or our per-cmd markers will tell us.
- Are the `btf_offsets.rs` constants (DENTRY_D_INODE_OFFSET,
  FILE_F_INODE_OFFSET, INODE_I_INO_OFFSET, etc.) verified against
  this kernel's vmlinux at agent boot? Re-check after we localise
  the iteration-2 cutoff.

---

## 6. Next steps (this iteration)

After this commit lands, user runs the test block from the chat
message. Three categories of evidence we need:

1. **Attack matrix rc values** — unchanged baseline.
2. **`trace_pipe` markers** — every `nn-diag-*` line, with counts.
3. **`attach_btf_id` per LSM prog** + matching vmlinux BTF id, so
   we can confirm or deny the dispatch mystery for the three
   never-fires hooks.

After results: update §0 with the new table, §4 with the resolved
bugs, §5/§6 with the next question.
